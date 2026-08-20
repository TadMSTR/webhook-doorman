"""The sink contract.

A sink delivers one event to one destination. **No sink knows its source.** If a sink ever needs
`if source == "github"`, routing has leaked into delivery and the abstraction that makes this a
router rather than four glued-together listeners has stopped being real.

Failure vocabulary, and the distinction is load-bearing:

* `SinkError` — retryable. A timeout, a 5xx, a connection refused. The engine schedules a backoff.
* `PermanentSinkError` — terminal. A 4xx, a malformed template, a sink that cannot be configured.
  Straight to the DLQ, because five identical failures with exponential backoff only delay the
  moment an operator finds out.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol

import httpx

from ..errors import PermanentSinkError, SinkError


@dataclass(frozen=True)
class DeliveryOutcome:
    """What happened on one delivery attempt."""

    response_code: int | None
    latency_ms: int


class Sink(Protocol):
    """Deliver one event's rendered content to one destination."""

    name: str

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        """Send the event.

        Args:
            context: the template namespace for this event.
            client: a shared HTTP client. Sinks do not create their own — connection reuse and
                the configured timeout belong to the engine.

        Raises:
            SinkError: retryable failure.
            PermanentSinkError: terminal failure.
        """
        ...


class HttpSinkBase:
    """Shared HTTP mechanics: timing, status classification, error translation.

    Status handling is the part worth stating explicitly. 4xx is permanent *except* 408 and 429,
    which are the two the server is explicitly asking you to try again. On those, and on 5xx,
    a `Retry-After` header is carried back to the engine on the `SinkError` rather than
    discarded — see `parse_retry_after`.
    """

    name: str

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> DeliveryOutcome:
        started = time.monotonic()
        try:
            response = await client.request(method, url, **kwargs)
        except UnicodeError as exc:
            # httpx encodes header values as ASCII, so a non-ASCII header raises from inside
            # `client.request` rather than arriving as an HTTP status. Encoding failures are
            # deterministic — the same bytes fail identically every time — so five attempts with
            # backoff only delay the moment an operator finds out. Fail to the DLQ on the first.
            # Sinks that render event content into a header should encode it themselves (see
            # `NtfySink_`); this is the net under them, and it is what keeps a sink safe by
            # default when its message routinely carries an em-dash or an emoji.
            raise PermanentSinkError(f"{self.name}: cannot encode request: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise SinkError(f"{self.name}: timeout after {_elapsed(started)}ms: {exc}") from exc
        except httpx.HTTPError as exc:
            raise SinkError(f"{self.name}: transport error: {exc}") from exc

        latency = _elapsed(started)
        code = response.status_code

        if code < 400:
            return DeliveryOutcome(response_code=code, latency_ms=latency)

        detail = response.text[:200]
        if code in (408, 429) or code >= 500:
            # A destination that says when to come back is answering the question the backoff
            # curve is guessing at. Read it on every retryable status rather than only 429 —
            # `Retry-After` is defined for 503 as well. The value is untrusted; the engine
            # clamps it, because a sink has no access to `delivery.max_backoff_seconds`.
            raise SinkError(
                f"{self.name}: HTTP {code}: {detail}",
                retry_after=parse_retry_after(response.headers.get("retry-after")),
            )
        raise PermanentSinkError(f"{self.name}: HTTP {code}: {detail}")


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait, read from a `Retry-After` header. `None` if absent or unreadable.

    Both forms in RFC 9110 §10.2.3 are accepted: delta-seconds (`Retry-After: 7`) and an
    HTTP-date (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`). A date already in the past gives
    `0.0` — "come back now" — rather than a negative delay.

    An unparseable value returns `None`, so the caller falls back to its own backoff curve. That
    direction matters: a destination sending garbage should end up with the normal backoff, not
    with a delay that rounds to zero and turns a retry budget into a tight loop.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None

    try:
        return max(0.0, float(raw))
    except ValueError:
        pass

    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        # An HTTP-date is GMT by definition; a naive result means the sender omitted the zone.
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
