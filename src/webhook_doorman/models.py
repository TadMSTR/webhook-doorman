"""Data carried between the ingest path, the store and the delivery engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    """Timezone-aware UTC now. Every timestamp in this package goes through here."""
    return datetime.now(UTC)


class EventStatus(str, Enum):
    RECEIVED = "received"
    DISPATCHED = "dispatched"
    FAILED = "failed"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXHAUSTED = "exhausted"


@dataclass
class InboundEvent:
    """A verified request, redacted and ready to persist.

    `headers` and `body` are already redacted by the time an instance exists — the ingest path
    redacts before construction so there is no window in which an un-redacted event could be
    handed to the store by mistake.
    """

    source: str
    delivery_id: str
    event_type: str
    summary: str
    headers: dict[str, str]
    body: bytes
    payload: Any = None
    context: dict[str, Any] = field(default_factory=dict)
    sinks: list[str] = field(default_factory=list)
    verified: bool = True
    received_at: datetime = field(default_factory=utcnow)

    def template_context(self) -> dict[str, Any]:
        """The namespace a sink template renders against."""
        return {
            "source": self.source,
            "delivery_id": self.delivery_id,
            "event_type": self.event_type,
            "summary": self.summary,
            "payload": self.payload,
            "received_at": self.received_at.isoformat(),
            **self.context,
        }


@dataclass
class StoredEvent:
    """An event as read back from the store."""

    id: int
    source: str
    delivery_id: str
    event_type: str
    summary: str
    headers: dict[str, str]
    body: bytes
    payload: Any
    context: dict[str, Any]
    verified: bool
    status: EventStatus
    received_at: datetime

    def template_context(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "delivery_id": self.delivery_id,
            "event_type": self.event_type,
            "summary": self.summary,
            "payload": self.payload,
            "received_at": self.received_at.isoformat(),
            **self.context,
        }


@dataclass
class Delivery:
    """One (event, sink) pair and its retry state."""

    id: int
    event_id: int
    sink: str
    attempt: int
    status: DeliveryStatus
    next_attempt_at: datetime | None = None
    response_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class DlqEntry:
    """One dead-lettered delivery, as `GET /admin/dlq` reports it.

    **Failure metadata only — no payload, no headers, no rendered body.** The question this
    answers is "what failed, why, and which `event_id` do I replay"; the event body is already
    retrievable by replaying it. A list endpoint that returned stored request bodies would be a
    far larger exfiltration surface than one that returns why a POST got a 400, and it would be
    reachable with the single admin token rather than requiring a deliberate replay.

    `id` is the DLQ row id and exists to be a pagination cursor. `event_id` is what you hand to
    `POST /admin/replay/{event_id}`; they are different numbers and confusing them replays the
    wrong event.
    """

    id: int
    event_id: int
    source: str
    sink: str
    attempt: int
    response_code: int | None
    error: str | None
    exhausted_at: datetime
