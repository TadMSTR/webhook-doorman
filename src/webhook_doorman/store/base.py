"""The storage seam.

Every SQL statement in this project lives behind this protocol. Nothing above `store/` knows
what a table is, and the engine talks only in the vocabulary below.

That is not abstraction for its own sake — it is where a second backend plugs in. Postgres or a
Redis-backed queue would be an additional implementation of `Store`, not an engine rewrite. The
revisit trigger is in ARCHITECTURE.md: more than one router replica, or sustained load past the
point a single writer can absorb. Until one of those is true, SQLite is the right answer and a
speculative second backend is just surface area.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ..models import Delivery, DlqEntry, EventStatus, HeldEntry, InboundEvent, StoredEvent


@runtime_checkable
class Store(Protocol):
    """Durable storage for events, delivery attempts and the dead-letter queue."""

    #: A random id for this database, stable once created. Set by `connect`. Prefixes
    #: idempotency keys sent to destinations so they stay unique across a re-created database.
    install_id: str

    async def connect(self) -> None:
        """Open the store and apply any schema migrations. Idempotent.

        An implementation that versions its schema must **read** the stored version before
        acting on it, and must decide by structure rather than by the version field alone. Until
        v0.4.0 the SQLite implementation did neither: it wrote its version number
        unconditionally, so an existing database reported a schema it had never been given. A
        version field that can lie is worse than no version field, because the next migrator
        trusts it and skips the work.

        Raises:
            StoreError: the stored schema is newer than this build understands. Opening it
                anyway is a downgrade, and a downgrade that writes is silent corruption.
        """

    async def close(self) -> None:
        """Release resources. Safe to call when never connected."""

    async def record_event(self, event: InboundEvent) -> tuple[int, bool]:
        """Persist an event.

        Returns:
            `(event_id, is_duplicate)`. A duplicate is an event whose `(source, delivery_id)`
            already exists; the returned id is the original's, and no new deliveries should be
            created for it.
        """
        ...

    async def enqueue_deliveries(self, event_id: int, sinks: list[str]) -> list[int]:
        """Create one pending delivery per sink. Returns the new delivery ids."""
        ...

    async def enqueue_first_deliveries(self, event_id: int, sinks: list[str]) -> list[int]:
        """Queue an event's first deliveries, atomically and at most once.

        Queues nothing, and returns `[]`, unless the event has no deliveries yet AND is still
        `received`. Both conditions are checked in the same statement as the insert. That is the
        guarantee the ingest path relies on: a redelivery resuming an interrupted dispatch cannot
        double the deliveries, and cannot queue an event the detector has just withheld.
        """
        ...

    async def has_deliveries(self, event_id: int) -> bool:
        """Whether any delivery row exists for the event."""
        ...

    async def claim_due_deliveries(self, now: datetime, limit: int) -> list[Delivery]:
        """Atomically move due pending deliveries to `in_flight` and return them."""
        ...

    async def mark_delivered(
        self, delivery_id: int, response_code: int | None, latency_ms: int
    ) -> None:
        """Record a successful attempt."""

    async def mark_retry(
        self,
        delivery_id: int,
        *,
        error: str,
        response_code: int | None,
        latency_ms: int,
        next_attempt_at: datetime,
    ) -> None:
        """Record a failed attempt that will be retried."""

    async def mark_exhausted(
        self,
        delivery_id: int,
        *,
        error: str,
        response_code: int | None,
        latency_ms: int,
        exhausted_at: datetime,
    ) -> None:
        """Record a terminal failure and add it to the dead-letter queue."""

    async def get_event(self, event_id: int) -> StoredEvent | None:
        """Read one event back, for replay."""
        ...

    async def list_dlq(self, *, limit: int, before_id: int | None = None) -> list[DlqEntry]:
        """Dead-lettered deliveries, newest first, for `GET /admin/dlq`.

        Args:
            limit: maximum rows to return. The caller is expected to have clamped this; an
                implementation must not treat it as unbounded.
            before_id: return only rows with a lower `id` than this — the cursor from the last
                row of the previous page.

        **Keyset pagination, not `OFFSET`.** The sweep deletes DLQ rows on a retention timer
        while an operator is paging, and under `OFFSET` every deletion behind the cursor shifts
        the window and silently skips a row. Skipping rows in the queue of things that failed is
        the one place that is least acceptable.
        """
        ...

    async def record_detection(
        self,
        event_id: int,
        *,
        detection: dict | None,
        status: EventStatus,
        quarantined_at: datetime | None,
    ) -> None:
        """Record a detector verdict and the status it produced, in one write.

        `detection` is `None` only when the detector could not evaluate the event — which is a
        different fact from a score of zero and is stored as a different value.
        """

    async def release_event(self, event_id: int) -> bool:
        """Return a quarantined event to `received`. The caller queues the deliveries.

        Returns whether THIS call did it. The status test and the write are one statement, so of
        two concurrent releases exactly one gets `True`, and only that one may enqueue.
        """
        ...

    async def release_claim(self, delivery_id: int, next_attempt_at: datetime) -> bool:
        """Hand an `in_flight` delivery back to `pending`, due at `next_attempt_at`.

        For a delivery whose attempt raised in the engine rather than the sink, so it is not left
        claimed until the next restart. It counts as an attempt: a failure that repeats on every
        pass (an event that cannot be read back, a full disk) must reach `max_attempts` and the
        DLQ, not loop for ever.
        """
        ...

    async def list_held(self, *, limit: int, before_id: int | None = None) -> list[HeldEntry]:
        """Quarantined events, newest first, for `GET /admin/held`.

        Same keyset rule and same metadata-only rule as `list_dlq` — see `HeldEntry`.
        """
        ...

    async def requeue_incomplete(self) -> int:
        """Return any `pending`/`in_flight` delivery to `pending` and make it due now.

        Called once at startup. A process killed mid-delivery leaves rows marked `in_flight`
        with nothing running to finish them; without this they would sit there forever, which
        is a lost event wearing a database row's clothes.

        Returns:
            The number of deliveries re-queued.
        """
        ...

    async def sweep(self, *, events_before: datetime, dlq_before: datetime) -> tuple[int, int]:
        """Delete old settled events and old DLQ entries.

        An event is only swept once every one of its deliveries has settled — a retry still in
        backoff must outlive the retention window rather than vanish mid-flight.

        Returns:
            `(events_deleted, dlq_deleted)`.
        """
        ...

    async def stats(self) -> dict[str, int]:
        """Counts by table and delivery status, for `/health` and operator sanity."""
        ...
