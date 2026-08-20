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
    which are the two the server is explicitly asking you to try again.
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
            raise SinkError(f"{self.name}: HTTP {code}: {detail}")
        raise PermanentSinkError(f"{self.name}: HTTP {code}: {detail}")


def _elapsed(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
