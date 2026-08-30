"""Schema versioning: the migration path, and the refusal to open a newer database.

Until v0.4.0 `SqliteStore.connect()` ran `CREATE TABLE IF NOT EXISTS` and then wrote
`PRAGMA user_version` without ever reading it. On an existing database that combination is
worse than a no-op: the column is not created *and* the version is bumped anyway, so the
version field reports a schema the file does not have. `test_v1_database_is_not_trusted_to
_self_report` pins the reasoning that replaced it — table presence decides, not the pragma.

Every fixture here builds a genuine v0.3.0 database from the DDL that shipped in v0.3.0,
copied verbatim below rather than imported. Importing the current `_SCHEMA` would make the
migration tests pass by construction the moment someone edited it.
"""

from __future__ import annotations

import sqlite3

import pytest

from webhook_doorman.errors import StoreError
from webhook_doorman.models import EventStatus, InboundEvent, utcnow
from webhook_doorman.store import SqliteStore
from webhook_doorman.store.sqlite import _MIGRATIONS, SCHEMA_VERSION

# The `events` DDL exactly as v0.3.0 (f9e1258) shipped it. Frozen on purpose: this is the
# shape of every database already on disk in the field, and it must not track edits to
# `_SCHEMA`. The other three tables are unchanged by this build and are created here so a
# migrated database is comparable to a fresh one.
V1_SCHEMA = """
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


def build_v1_database(path, *, rows: int = 0, user_version: int = 1) -> None:
    """Write a v0.3.0-shaped database, optionally with events in it."""
    db = sqlite3.connect(path, isolation_level=None)
    try:
        db.executescript(V1_SCHEMA)
        for index in range(rows):
            db.execute(
                """
                INSERT INTO events
                    (source, delivery_id, event_type, summary, received_at,
                     headers_json, body, context_json, verified, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "github",
                    f"legacy-{index}",
                    "issues.opened",
                    f"legacy summary {index}",
                    utcnow().isoformat(),
                    "{}",
                    b'{"legacy": true}',
                    "{}",
                    1,
                    EventStatus.RECEIVED.value,
                ),
            )
        db.execute(f"PRAGMA user_version={user_version}")
    finally:
        db.close()


def schema_of(path) -> dict:
    """Column definitions and index names, as a comparable structure."""
    db = sqlite3.connect(path)
    try:
        columns = {
            table: [(r[1], r[2], r[3], r[4]) for r in db.execute(f"PRAGMA table_info({table})")]
            for table in ("events", "deliveries", "dlq")
        }
        indexes = sorted(
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
            )
        )
        return {"columns": columns, "indexes": indexes}
    finally:
        db.close()


def user_version_of(path) -> int:
    db = sqlite3.connect(path)
    try:
        return int(db.execute("PRAGMA user_version").fetchone()[0])
    finally:
        db.close()


class TestFreshDatabase:
    async def test_reaches_current_version(self, tmp_path):
        path = tmp_path / "fresh.db"
        store = SqliteStore(path)
        await store.connect()
        await store.close()
        assert user_version_of(path) == SCHEMA_VERSION

    async def test_has_the_new_columns(self, tmp_path):
        path = tmp_path / "fresh.db"
        store = SqliteStore(path)
        await store.connect()
        await store.close()
        names = [column[0] for column in schema_of(path)["columns"]["events"]]
        assert "untrusted_fields_json" in names
        assert "detection_json" in names
        assert "quarantined_at" in names


class TestMigrationFromV1:
    async def test_gains_the_new_columns(self, tmp_path):
        path = tmp_path / "legacy.db"
        build_v1_database(path)
        store = SqliteStore(path)
        await store.connect()
        await store.close()

        names = [column[0] for column in schema_of(path)["columns"]["events"]]
        assert "untrusted_fields_json" in names
        assert "detection_json" in names
        assert "quarantined_at" in names
        assert user_version_of(path) == SCHEMA_VERSION

    async def test_keeps_every_row_and_defaults_the_new_columns(self, tmp_path):
        path = tmp_path / "legacy.db"
        build_v1_database(path, rows=3)
        store = SqliteStore(path)
        await store.connect()
        try:
            cursor = await store.db.execute(
                "SELECT delivery_id, summary, untrusted_fields_json, detection_json, "
                "quarantined_at FROM events ORDER BY id"
            )
            rows = await cursor.fetchall()
        finally:
            await store.close()

        assert [row["delivery_id"] for row in rows] == ["legacy-0", "legacy-1", "legacy-2"]
        assert [row["summary"] for row in rows] == [
            "legacy summary 0",
            "legacy summary 1",
            "legacy summary 2",
        ]
        # The whole point of a default on an ALTER: existing rows are readable, not NULL-ridden.
        assert [row["untrusted_fields_json"] for row in rows] == ["[]", "[]", "[]"]
        # Nullable, and NULL means "never evaluated" — distinct from a score of zero.
        assert [row["detection_json"] for row in rows] == [None, None, None]
        assert [row["quarantined_at"] for row in rows] == [None, None, None]

    async def test_a_migrated_store_still_takes_writes(self, tmp_path):
        """The migration is not just DDL — the migrated file has to work."""
        path = tmp_path / "legacy.db"
        build_v1_database(path, rows=1)
        store = SqliteStore(path)
        await store.connect()
        try:
            event_id, duplicate = await store.record_event(
                InboundEvent(
                    source="github",
                    delivery_id="post-migration",
                    event_type="issues.opened",
                    summary="written after the migration",
                    headers={},
                    body=b"{}",
                )
            )
            assert duplicate is False
            stored = await store.get_event(event_id)
        finally:
            await store.close()
        assert stored is not None
        assert stored.summary == "written after the migration"

    async def test_is_idempotent_across_two_connects(self, tmp_path):
        path = tmp_path / "legacy.db"
        build_v1_database(path, rows=2)

        for _ in range(2):
            store = SqliteStore(path)
            await store.connect()
            await store.close()

        assert user_version_of(path) == SCHEMA_VERSION
        db = sqlite3.connect(path)
        try:
            assert int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == 2
        finally:
            db.close()

    async def test_v1_database_is_not_trusted_to_self_report(self, tmp_path):
        """`user_version=0` on a populated file is read as the baseline, not as fresh.

        A database written by the pre-v0.4.0 code can carry a version it does not have. Table
        presence is the signal that cannot lie, so a populated file with a zeroed pragma still
        migrates rather than being handed `_SCHEMA` as if it were new.
        """
        path = tmp_path / "unversioned.db"
        build_v1_database(path, rows=1, user_version=0)
        store = SqliteStore(path)
        await store.connect()
        await store.close()

        names = [column[0] for column in schema_of(path)["columns"]["events"]]
        assert "untrusted_fields_json" in names
        assert user_version_of(path) == SCHEMA_VERSION
        db = sqlite3.connect(path)
        try:
            assert int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == 1
        finally:
            db.close()


class TestMigratedFromIsReported:
    """`store_ready` names the version it came from, and it must name a version that existed."""

    @staticmethod
    def _store_ready(monkeypatch) -> list[dict]:
        import structlog

        from webhook_doorman.store import sqlite as sqlite_module

        entries: list[dict] = []

        def capture(_logger, _name, event_dict):
            entries.append(dict(event_dict))
            raise structlog.DropEvent

        saved = structlog.get_config()
        structlog.configure(
            processors=[capture],
            wrapper_class=structlog.make_filtering_bound_logger(0),
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=False,
        )
        # Rebound because `configure_logging` sets `cache_logger_on_first_use`: once any earlier
        # test has logged through the module's lazy proxy, the proxy has permanently become the
        # logger it was bound to, and reconfiguring alone would not reach it.
        monkeypatch.setattr(
            sqlite_module, "log", structlog.get_logger("webhook_doorman.store.sqlite")
        )
        return entries, saved

    async def test_a_zero_versioned_database_reports_migrating_from_the_baseline(
        self, tmp_path, monkeypatch
    ):
        """Not 0. A database written before this build can report a version it never had, and a
        log line saying `migrated_from: 0` names a schema version that has never existed."""
        import structlog

        entries, saved = self._store_ready(monkeypatch)
        try:
            path = tmp_path / "unversioned.db"
            build_v1_database(path, rows=1, user_version=0)
            store = SqliteStore(path)
            await store.connect()
            await store.close()
        finally:
            structlog.configure(**saved)

        ready = [e for e in entries if e.get("event") == "store_ready"]
        assert ready and ready[0]["migrated_from"] == 1

    async def test_a_fresh_database_reports_no_migration_at_all(self, tmp_path, monkeypatch):
        """Absence of the key means "already current", not "the migrator did not run"."""
        import structlog

        entries, saved = self._store_ready(monkeypatch)
        try:
            store = SqliteStore(tmp_path / "fresh.db")
            await store.connect()
            await store.close()
        finally:
            structlog.configure(**saved)

        ready = [e for e in entries if e.get("event") == "store_ready"]
        assert ready and "migrated_from" not in ready[0]


class TestNewerDatabaseIsRefused:
    async def test_refuses_to_open(self, tmp_path):
        path = tmp_path / "future.db"
        build_v1_database(path, user_version=SCHEMA_VERSION + 1)
        store = SqliteStore(path)
        with pytest.raises(StoreError) as excinfo:
            await store.connect()
        await store.close()

        message = str(excinfo.value)
        assert str(SCHEMA_VERSION + 1) in message
        assert str(SCHEMA_VERSION) in message

    async def test_leaves_the_database_untouched(self, tmp_path):
        """A refusal must not be a partial upgrade."""
        path = tmp_path / "future.db"
        build_v1_database(path, rows=1, user_version=SCHEMA_VERSION + 1)
        before = schema_of(path)

        store = SqliteStore(path)
        with pytest.raises(StoreError):
            await store.connect()
        await store.close()

        assert schema_of(path) == before
        assert user_version_of(path) == SCHEMA_VERSION + 1


class TestSchemaRosters:
    async def test_fresh_and_migrated_schemas_match(self, tmp_path):
        """The two ways to reach the current schema must produce the same schema.

        `_SCHEMA` (fresh) and `_MIGRATIONS` (existing) are two descriptions of one thing. Adding
        a column to one and forgetting the other is the drift this compares for, rather than
        leaving it to review — and it fails whichever of the two was forgotten.
        """
        fresh = tmp_path / "fresh.db"
        store = SqliteStore(fresh)
        await store.connect()
        await store.close()

        migrated = tmp_path / "migrated.db"
        build_v1_database(migrated)
        store = SqliteStore(migrated)
        await store.connect()
        await store.close()

        assert schema_of(migrated) == schema_of(fresh)
        assert user_version_of(migrated) == user_version_of(fresh)

    def test_schema_version_is_derived_from_the_migration_table(self):
        """One roster, not two. `SCHEMA_VERSION` cannot drift from `_MIGRATIONS` by design."""
        assert max(_MIGRATIONS) == SCHEMA_VERSION
        assert SCHEMA_VERSION > 1, "version 1 is the baseline; migrations start at 2"

    def test_version_and_ddl_roll_back_together(self, tmp_path):
        """The claim `_MIGRATIONS` documents: a crash mid-step leaves neither half applied.

        `PRAGMA user_version` is journaled with the DDL, so the per-version transaction is
        genuinely atomic. If SQLite ever stopped doing that, a crash would leave a bumped
        version on an unmigrated schema — the exact defect v0.4.0 exists to remove.
        """
        path = tmp_path / "atomic.db"
        build_v1_database(path)
        db = sqlite3.connect(path, isolation_level=None)
        try:
            db.execute("BEGIN")
            db.execute("ALTER TABLE events ADD COLUMN probe TEXT")
            db.execute("PRAGMA user_version=99")
            db.execute("ROLLBACK")

            assert int(db.execute("PRAGMA user_version").fetchone()[0]) == 1
            assert "probe" not in [r[1] for r in db.execute("PRAGMA table_info(events)")]
        finally:
            db.close()


class TestMigrationFailure:
    async def test_a_failing_step_rolls_back_and_leaves_the_version_alone(
        self, tmp_path, monkeypatch
    ):
        """A half-applied migration is the one outcome worse than an un-applied one.

        The DDL and the version bump share a transaction, so a statement that raises must undo
        the statements before it *and* leave `user_version` at the value it had. Otherwise the
        next start reads a version whose schema was never finished — the same lie, arrived at
        by a different route.
        """
        path = tmp_path / "broken.db"
        build_v1_database(path, rows=1)

        monkeypatch.setitem(
            _MIGRATIONS,
            SCHEMA_VERSION,
            (
                "ALTER TABLE events ADD COLUMN applied_first TEXT",
                "ALTER TABLE events ADD COLUMN this_is_not_valid_sql(((",
            ),
        )

        store = SqliteStore(path)
        with pytest.raises(sqlite3.OperationalError):
            await store.connect()
        await store.close()

        names = [column[0] for column in schema_of(path)["columns"]["events"]]
        assert "applied_first" not in names, "the first statement was not rolled back"
        assert user_version_of(path) == 1, "the version moved despite the migration failing"
        db = sqlite3.connect(path)
        try:
            assert int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0]) == 1
        finally:
            db.close()
