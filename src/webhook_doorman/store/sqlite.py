"""SQLite implementation of `Store`. WAL mode, one file, no server.

Why SQLite and not Postgres: routing is stateless and the database earns its place on three
things only — dedup, retry, and being able to answer "did that delivery arrive?". None of those
need multi-writer concurrency or replication at the volumes this handles, and a second container
plus a new thing to back up is a real cost paid by every adopter.

Durability settings, and the reasoning, because these are the two knobs that decide whether the
crash-safety claim is true:

* **`journal_mode=WAL`** — readers do not block the writer, and a crash rolls back to the last
  committed transaction rather than corrupting the file.
* **`synchronous=NORMAL`** — with WAL this is the documented safe pairing. Committed
  transactions survive a *process* crash; a small window exists for an OS-level crash or power
  loss. `FULL` closes that window at roughly an fsync per commit. NORMAL is the right default
  for a webhook router: the producer retries what we did not acknowledge, so the failure mode
  is a duplicate delivery that dedup absorbs, not a silent loss.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import aiosqlite
import structlog

from ..models import (
    Delivery,
    DeliveryStatus,
    EventStatus,
    InboundEvent,
    StoredEvent,
)

log = structlog.get_logger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT    NOT NULL,
    delivery_id   TEXT    NOT NULL,
    event_type    TEXT    NOT NULL DEFAULT '',
    summary       TEXT    NOT NULL DEFAULT '',
    received_at   TEXT    NOT NULL,
    headers_json  TEXT    NOT NULL DEFAULT '{}',
    body          BLOB    NOT NULL,
    context_json  TEXT    NOT NULL DEFAULT '{}',
    verified      INTEGER NOT NULL DEFAULT 1,
    status        TEXT    NOT NULL DEFAULT 'received'
);

-- The dedup key. A producer retrying a delivery hits this and is answered 200, not 4xx.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events (source, delivery_id);
CREATE INDEX IF NOT EXISTS idx_events_received ON events (received_at);

CREATE TABLE IF NOT EXISTS deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    sink            TEXT    NOT NULL,
    attempt         INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'pending',
    response_code   INTEGER,
    latency_ms      INTEGER,
    error           TEXT,
    next_attempt_at TEXT,
    updated_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_deliveries_event ON deliveries (event_id);

CREATE TABLE IF NOT EXISTS dlq (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id  INTEGER NOT NULL REFERENCES deliveries (id) ON DELETE CASCADE,
    exhausted_at TEXT    NOT NULL,
    last_error   TEXT
);

CREATE INDEX IF NOT EXISTS idx_dlq_exhausted ON dlq (exhausted_at);
"""


def _iso(value: datetime) -> str:
    return value.isoformat()


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class SqliteStore:
    """`Store` backed by a single SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._db: aiosqlite.Connection | None = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("store is not connected; call connect() first")
        return self._db

    async def connect(self) -> None:
        if self._db is not None:
            return
        if self.path.parent and str(self.path.parent) not in ("", "."):
            # Explicit mode. Left to the default, the directory ACL is whatever the process
            # umask happens to be, which is not something a container image should decide by
            # accident for a directory holding the event log.
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        self._db = await aiosqlite.connect(self.path, isolation_level=None)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._db.executescript(_SCHEMA)
        await self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        log.info("store_ready", path=str(self.path), schema_version=SCHEMA_VERSION)

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    # -- ingest ------------------------------------------------------------------------

    async def record_event(self, event: InboundEvent) -> tuple[int, bool]:
        cursor = await self.db.execute(
            """
            INSERT OR IGNORE INTO events
                (source, delivery_id, event_type, summary, received_at,
                 headers_json, body, context_json, verified, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.source,
                event.delivery_id,
                event.event_type,
                event.summary,
                _iso(event.received_at),
                json.dumps(event.headers),
                event.body,
                json.dumps(event.context, default=str),
                int(event.verified),
                EventStatus.RECEIVED.value,
            ),
        )
        if cursor.rowcount:
            return int(cursor.lastrowid), False

        # INSERT OR IGNORE swallowed it: the unique index on (source, delivery_id) already had
        # this delivery. Return the original id so the caller can report the dedup honestly.
        row = await self._fetchone(
            "SELECT id FROM events WHERE source = ? AND delivery_id = ?",
            (event.source, event.delivery_id),
        )
        return (int(row["id"]), True) if row else (0, True)

    async def enqueue_deliveries(self, event_id: int, sinks: list[str]) -> list[int]:
        ids: list[int] = []
        now = _iso(_utcnow())
        for sink in sinks:
            cursor = await self.db.execute(
                """
                INSERT INTO deliveries
                    (event_id, sink, attempt, status, next_attempt_at, updated_at)
                VALUES (?, ?, 0, ?, ?, ?)
                """,
                (event_id, sink, DeliveryStatus.PENDING.value, now, now),
            )
            ids.append(int(cursor.lastrowid))
        return ids

    # -- delivery ----------------------------------------------------------------------

    async def claim_due_deliveries(self, now: datetime, limit: int) -> list[Delivery]:
        cursor = await self.db.execute(
            """
            UPDATE deliveries
               SET status = ?, updated_at = ?
             WHERE id IN (
                   SELECT id FROM deliveries
                    WHERE status = ?
                      AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                    ORDER BY next_attempt_at
                    LIMIT ?
             )
            RETURNING id, event_id, sink, attempt, status, next_attempt_at,
                      response_code, latency_ms, error
            """,
            (
                DeliveryStatus.IN_FLIGHT.value,
                _iso(now),
                DeliveryStatus.PENDING.value,
                _iso(now),
                limit,
            ),
        )
        rows = await cursor.fetchall()
        return [_row_to_delivery(row) for row in rows]

    async def mark_delivered(
        self, delivery_id: int, response_code: int | None, latency_ms: int
    ) -> None:
        await self.db.execute(
            """
            UPDATE deliveries
               SET status = ?, attempt = attempt + 1, response_code = ?, latency_ms = ?,
                   error = NULL, next_attempt_at = NULL, updated_at = ?
             WHERE id = ?
            """,
            (
                DeliveryStatus.DELIVERED.value,
                response_code,
                latency_ms,
                _iso(_utcnow()),
                delivery_id,
            ),
        )
        await self._settle_event_for(delivery_id)

    async def mark_retry(
        self,
        delivery_id: int,
        *,
        error: str,
        response_code: int | None,
        latency_ms: int,
        next_attempt_at: datetime,
    ) -> None:
        await self.db.execute(
            """
            UPDATE deliveries
               SET status = ?, attempt = attempt + 1, response_code = ?, latency_ms = ?,
                   error = ?, next_attempt_at = ?, updated_at = ?
             WHERE id = ?
            """,
            (
                DeliveryStatus.PENDING.value,
                response_code,
                latency_ms,
                error[:1000],
                _iso(next_attempt_at),
                _iso(_utcnow()),
                delivery_id,
            ),
        )

    async def mark_exhausted(
        self,
        delivery_id: int,
        *,
        error: str,
        response_code: int | None,
        latency_ms: int,
        exhausted_at: datetime,
    ) -> None:
        await self.db.execute(
            """
            UPDATE deliveries
               SET status = ?, attempt = attempt + 1, response_code = ?, latency_ms = ?,
                   error = ?, next_attempt_at = NULL, updated_at = ?
             WHERE id = ?
            """,
            (
                DeliveryStatus.EXHAUSTED.value,
                response_code,
                latency_ms,
                error[:1000],
                _iso(exhausted_at),
                delivery_id,
            ),
        )
        await self.db.execute(
            "INSERT INTO dlq (delivery_id, exhausted_at, last_error) VALUES (?, ?, ?)",
            (delivery_id, _iso(exhausted_at), error[:1000]),
        )
        await self._settle_event_for(delivery_id, failed=True)

    async def requeue_incomplete(self) -> int:
        cursor = await self.db.execute(
            """
            UPDATE deliveries
               SET status = ?, next_attempt_at = ?, updated_at = ?
             WHERE status IN (?, ?)
            """,
            (
                DeliveryStatus.PENDING.value,
                _iso(_utcnow()),
                _iso(_utcnow()),
                DeliveryStatus.PENDING.value,
                DeliveryStatus.IN_FLIGHT.value,
            ),
        )
        count = cursor.rowcount or 0
        if count:
            log.info("deliveries_requeued", count=count)
        return count

    # -- reads -------------------------------------------------------------------------

    async def get_event(self, event_id: int) -> StoredEvent | None:
        row = await self._fetchone("SELECT * FROM events WHERE id = ?", (event_id,))
        if row is None:
            return None
        body = bytes(row["body"])
        return StoredEvent(
            id=int(row["id"]),
            source=row["source"],
            delivery_id=row["delivery_id"],
            event_type=row["event_type"],
            summary=row["summary"],
            headers=json.loads(row["headers_json"]),
            body=body,
            payload=_safe_json(body),
            context=json.loads(row["context_json"]),
            verified=bool(row["verified"]),
            status=EventStatus(row["status"]),
            received_at=datetime.fromisoformat(row["received_at"]),
        )

    async def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for table in ("events", "deliveries", "dlq"):
            row = await self._fetchone(f"SELECT COUNT(*) AS n FROM {table}")
            out[table] = int(row["n"]) if row else 0
        cursor = await self.db.execute(
            "SELECT status, COUNT(*) AS n FROM deliveries GROUP BY status"
        )
        for row in await cursor.fetchall():
            out[f"deliveries_{row['status']}"] = int(row["n"])
        return out

    # -- maintenance -------------------------------------------------------------------

    async def sweep(self, *, events_before: datetime, dlq_before: datetime) -> tuple[int, int]:
        dlq_cursor = await self.db.execute(
            "DELETE FROM dlq WHERE exhausted_at < ?", (_iso(dlq_before),)
        )
        dlq_deleted = dlq_cursor.rowcount or 0

        # An event survives the retention window while any of its deliveries is still unsettled.
        # Sweeping one mid-retry would delete the payload the retry is about to send.
        events_cursor = await self.db.execute(
            """
            DELETE FROM events
             WHERE received_at < ?
               AND NOT EXISTS (
                   SELECT 1 FROM deliveries d
                    WHERE d.event_id = events.id AND d.status IN (?, ?)
               )
            """,
            (_iso(events_before), DeliveryStatus.PENDING.value, DeliveryStatus.IN_FLIGHT.value),
        )
        events_deleted = events_cursor.rowcount or 0
        if events_deleted or dlq_deleted:
            log.info("retention_sweep", events_deleted=events_deleted, dlq_deleted=dlq_deleted)
        return events_deleted, dlq_deleted

    # -- internals ---------------------------------------------------------------------

    async def _fetchone(self, sql: str, params: tuple = ()) -> aiosqlite.Row | None:
        cursor = await self.db.execute(sql, params)
        return await cursor.fetchone()

    async def _settle_event_for(self, delivery_id: int, failed: bool = False) -> None:
        """Roll a delivery outcome up to its event's status.

        `failed` wins: an event with one exhausted delivery is `failed` even if its other sinks
        succeeded, because that is the state an operator needs to see.
        """
        row = await self._fetchone("SELECT event_id FROM deliveries WHERE id = ?", (delivery_id,))
        if row is None:
            return
        event_id = int(row["event_id"])

        pending = await self._fetchone(
            """
            SELECT COUNT(*) AS n FROM deliveries
             WHERE event_id = ? AND status IN (?, ?)
            """,
            (event_id, DeliveryStatus.PENDING.value, DeliveryStatus.IN_FLIGHT.value),
        )
        if pending and int(pending["n"]) > 0:
            return

        exhausted = await self._fetchone(
            "SELECT COUNT(*) AS n FROM deliveries WHERE event_id = ? AND status = ?",
            (event_id, DeliveryStatus.EXHAUSTED.value),
        )
        any_failed = failed or (exhausted is not None and int(exhausted["n"]) > 0)
        status = EventStatus.FAILED if any_failed else EventStatus.DISPATCHED
        await self.db.execute("UPDATE events SET status = ? WHERE id = ?", (status.value, event_id))


def _row_to_delivery(row: aiosqlite.Row) -> Delivery:
    return Delivery(
        id=int(row["id"]),
        event_id=int(row["event_id"]),
        sink=row["sink"],
        attempt=int(row["attempt"]),
        status=DeliveryStatus(row["status"]),
        next_attempt_at=_parse(row["next_attempt_at"]),
        response_code=row["response_code"],
        latency_ms=row["latency_ms"],
        error=row["error"],
    )


def _safe_json(body: bytes):
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _utcnow() -> datetime:
    from ..models import utcnow

    return utcnow()
