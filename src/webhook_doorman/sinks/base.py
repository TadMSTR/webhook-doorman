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

import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import Enum, auto
from typing import Any, Protocol

import httpx

from ..errors import PermanentSinkError, SinkError

# How much of a destination's response body travels back in an error message. Chosen small on
# purpose: 200 characters of an arbitrary error page is rarely more diagnostic than 80, and it is
# 120 more characters of someone else's output to store, log and export.
DESTINATION_BODY_CHARS = 80


@dataclass(frozen=True)
class DeliveryOutcome:
    """What happened on one delivery attempt."""

    response_code: int | None
    latency_ms: int


class Disposition(Enum):
    """The three things a response can mean, mapped onto the failure vocabulary above."""

    DELIVERED = auto()
    RETRYABLE = auto()
    PERMANENT = auto()


@dataclass(frozen=True)
class Verdict:
    """A classified response, and optionally why.

    `reason` replaces the response body in the resulting error message. It exists because the
    codes worth overriding are usually the ones with nothing useful in the body — a bare `204`
    yields `HTTP 204: ` and tells an operator nothing about which of its two meanings applied.
    """

    disposition: Disposition
    reason: str | None = None


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

    Status handling is the part worth stating explicitly. Only 2xx is delivered. 4xx is permanent
    *except* 408 and 429, which are the two the server is explicitly asking you to try again. On
    those, and on 5xx, a `Retry-After` header is carried back to the engine on the `SinkError`
    rather than discarded — see `parse_retry_after`.

    **3xx is permanent, not delivered.** The engine builds its client with
    `follow_redirects=False` on purpose, because a webhook URL embeds its own credential and
    following an attacker-influenced `Location` would hand that credential elsewhere. An
    un-followed redirect therefore delivers nothing, and counting it as success is the silent
    failure this class's `_classify` docstring warns about.

    That rule is a default, not a law: a destination that overloads a status code overrides
    `_classify`. See its docstring for when, and for why the safe direction is to prefer the
    error.
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
        # Both failure paths carry the elapsed time, not just the message. A timeout is the
        # slowest thing a sink does and a connect failure can take seconds to give up; recording
        # either as 0ms would put the worst latencies in the fastest bucket and flatter the
        # histogram exactly when the destination is at its worst.
        except httpx.TimeoutException as exc:
            raise SinkError(
                f"{self.name}: timeout after {_elapsed(started)}ms: {exc}",
                latency_ms=_elapsed(started),
            ) from exc
        except httpx.HTTPError as exc:
            raise SinkError(
                f"{self.name}: transport error: {exc}", latency_ms=_elapsed(started)
            ) from exc

        latency = _elapsed(started)
        code = response.status_code
        verdict = self._classify(response)

        if verdict.disposition is Disposition.DELIVERED:
            return DeliveryOutcome(response_code=code, latency_ms=latency)

        # The destination's own body, and therefore the one part of this message that is not
        # ours. It is carried because "HTTP 400" alone rarely says which field was wrong, but it
        # is cut short and redacted at the engine boundary before it is persisted or logged —
        # destinations have been known to echo a submitted token back in an error page, and
        # `redaction.py` runs at ingest only. See `Engine._redact_error`.
        detail = verdict.reason or response.text[:DESTINATION_BODY_CHARS]
        if verdict.disposition is Disposition.RETRYABLE:
            # A destination that says when to come back is answering the question the backoff
            # curve is guessing at. Read it on every retryable status rather than only 429 —
            # `Retry-After` is defined for 503 as well. The value is untrusted; the engine
            # clamps it, because a sink has no access to `delivery.max_backoff_seconds`.
            raise SinkError(
                f"{self.name}: HTTP {code}: {detail}",
                retry_after=parse_retry_after(response.headers.get("retry-after")),
                latency_ms=latency,
            )
        raise PermanentSinkError(f"{self.name}: HTTP {code}: {detail}", latency_ms=latency)

    def _classify(self, response: httpx.Response) -> Verdict:
        """What this response means. Override to correct a destination that disagrees with HTTP.

        The default is the status-code rule in this class's docstring, and it is right for most
        destinations. It is wrong for any API that overloads a code, and the two failure modes
        are not symmetric: a success misread as a failure produces a duplicate delivery an
        operator can see, while a *failure misread as a success* produces silence — no retry, no
        DLQ row, no log line above debug. `AppriseNotifySink` overrides this because apprise-api
        answers `204` when it has no valid URLs to notify, which the default reads as delivered.

        Override by returning `Verdict` for the codes you know about and delegating the rest:

            def _classify(self, response):
                if response.status_code == 204:
                    return Verdict(Disposition.PERMANENT, "reason an operator can act on")
                return super()._classify(response)

        This is also the seam for a destination that reports failure in the *body* of a 200 —
        Slack's `chat.postMessage` Web API returns `{"ok": false, "error": ...}` that way. Read
        `response.json()` here rather than adding a second check in `deliver`.
        """
        code = response.status_code
        if code < 300:
            return Verdict(Disposition.DELIVERED)
        if code < 400:
            return Verdict(Disposition.PERMANENT, _redirect_reason(response))
        if code in (408, 429) or code >= 500:
            return Verdict(Disposition.RETRYABLE)
        return Verdict(Disposition.PERMANENT)


def _redirect_reason(response: httpx.Response) -> str:
    """Why a 3xx is a configuration error, named concretely enough to act on.

    The `Location` value is destination-controlled, so it is truncated and carried as text only —
    nothing in this codebase follows it. It is here because "301 to https://..." tells an operator
    they typed `http://` in one glance, and a bare "HTTP 301" does not.
    """
    location = response.headers.get("location")
    target = f" to {location[:120]}" if location else ""
    return (
        f"destination redirected{target}; redirects are not followed because a webhook URL "
        f"carries its own credential — point the sink at the final URL"
    )


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait, read from a `Retry-After` header. `None` if absent or unreadable.

    Both forms in RFC 9110 §10.2.3 are accepted: delta-seconds (`Retry-After: 7`) and an
    HTTP-date (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`). A date already in the past gives
    `0.0` — "come back now" — rather than a negative delay.

    Everything else returns `None`, so the caller falls back to its own backoff curve. That
    direction is the safe one and it is worth being strict about, because this is the one field
    in the delivery path whose value comes from the destination:

    * **Non-finite.** `float()` happily accepts `nan`, `inf` and any integer long enough to
      overflow to `inf`. The engine's clamp would contain all of them today, but a parser that
      can hand back `inf` is one refactor away from an `inf` reaching an arithmetic that has no
      clamp — `_jittered(inf)` produces `nan`, and a `nan` delay is a delivery that is never due.
      Rejecting it here means the guarantee does not rest on the caller remembering to clamp.
    * **Negative delta-seconds.** Not a valid delta — RFC 9110 defines it as non-negative — and
      reading one as "retry now" lets a destination *accelerate* our retries at itself, spending
      the whole attempt budget as fast as the poll loop allows. A past HTTP-date is different:
      that genuinely means now, and is treated as `0.0`.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None

    try:
        seconds = float(raw)
    except ValueError:
        pass
    else:
        return seconds if math.isfinite(seconds) and seconds >= 0 else None

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
