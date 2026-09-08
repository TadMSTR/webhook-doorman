"""Data carried between the ingest path, the store and the delivery engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utcnow() -> datetime:
    """Timezone-aware UTC now. Every timestamp in this package goes through here."""
    return datetime.now(UTC)


class EventStatus(StrEnum):
    RECEIVED = "received"
    DISPATCHED = "dispatched"
    FAILED = "failed"
    #: Admitted, verified and stored, but refused by the source's `filter` — no sinks were
    #: queued. A terminal state: nothing settles it later, because there is nothing in flight.
    FILTERED = "filtered"
    #: Held by the detector under `on_detect: quarantine`. Stored, not dispatched, and
    #: **releasable** — `POST /admin/release/{event_id}` queues the deliveries that were
    #: withheld. This is the state `GET /admin/held` lists.
    QUARANTINED = "quarantined"
    #: Discarded by the detector under `on_detect: drop`. Stored with its verdict, never
    #: dispatched, and deliberately *not* releasable — that is the whole difference from
    #: `QUARANTINED`, and the reason the README names `drop` a footgun.
    DROPPED = "dropped"


class DeliveryStatus(StrEnum):
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
    status: EventStatus = EventStatus.RECEIVED
    untrusted_fields: list[str] = field(default_factory=list)
    """Template-context keys this event's parser filled from attacker-authored data.

    Declared by the parser and persisted with the event, so a replay - which rebuilds the event
    from the stored row and has no parser output to consult - fences exactly what the original
    delivery did. See `fencing` for why this is a list of names rather than a marker type.
    """
    filter_reason: str | None = None
    """Which gate in `SourceFilter` refused this event, when `status` is `FILTERED`.

    One of `filtering.FILTER_REASONS`. Carried on the event rather than returned alongside it so
    that the decision travels with the thing it was made about — the engine counts it after the
    dedup check, where it means "events filtered" rather than "requests filtered".
    """

    def template_context(self, *, fence: bool = False) -> dict[str, Any]:
        """The namespace a sink template renders against.

        `event_id` is absent here and present on `StoredEvent`: an inbound event has not been
        given an id yet. Delivery always renders a `StoredEvent`, so the key is available
        wherever a template can actually reach it.
        """
        return _template_context(self, fence=fence)


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
    untrusted_fields: list[str] = field(default_factory=list)

    def template_context(self, *, fence: bool = False) -> dict[str, Any]:
        return _template_context(self, fence=fence, event_id=self.id)


def _template_context(event, *, fence: bool, event_id: int | None = None) -> dict[str, Any]:
    """The shared template namespace for both event shapes.

    One function rather than two near-identical methods: the fencing rule has to be the same on
    the ingest path and the replay path, and two copies of it is how they would come to differ.
    """
    context: dict[str, Any] = {
        "source": event.source,
        "delivery_id": event.delivery_id,
        "event_type": event.event_type,
        "summary": event.summary,
        "payload": event.payload,
        "received_at": event.received_at.isoformat(),
        **event.context,
    }
    if event_id is not None:
        # A stable idempotency key, so an agent acting on this message can dedup its own
        # actions. It is the store's primary key, which is the only identifier here that is
        # ours rather than the producer's.
        context["event_id"] = event_id
    if not fence or not event.untrusted_fields:
        return context
    from .fencing import fence_context

    return fence_context(context, source=event.source, fields=event.untrusted_fields)


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
class HeldEntry:
    """One quarantined event, as `GET /admin/held` reports it.

    **Failure metadata only - no payload, no rendered body, no field content.** The same rule as
    `DlqEntry`, and here it matters more rather than less: the content being withheld is content
    a detector flagged as an injection attempt, and a list endpoint that returned it would hand
    that text to whatever reads the admin API. `rules` names what matched; the text that matched
    is not carried anywhere.

    `event_id` is both the identity and the pagination cursor here, unlike `DlqEntry` where they
    are different numbers - quarantine is a property of an event, not of a delivery.
    """

    event_id: int
    source: str
    event_type: str
    score: float | None
    rules: list[str]
    quarantined_at: datetime


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
