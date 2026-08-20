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

from ..models import Delivery, InboundEvent, StoredEvent


@runtime_checkable
class Store(Protocol):
    """Durable storage for events, delivery attempts and the dead-letter queue."""

    async def connect(self) -> None:
        """Open the store and apply any schema migrations. Idempotent."""

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
