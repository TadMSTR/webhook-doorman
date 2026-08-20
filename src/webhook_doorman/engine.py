"""Persist-then-dispatch, retry, dead-letter and retention.

The shape of this module is one decision: **the request handler's job ends at the database.**
It writes the event, returns 2xx, and stops. Dispatch belongs to a background worker.

That split is what turns a down sink from a lost event into a delayed one. It also stops a slow
sink from holding a producer's connection open — GitHub gives you ten seconds and then marks the
delivery failed, so a synchronous fan-out to three destinations makes the producer's view of
your reliability depend on the slowest one.

Three behaviours here are worth stating because the obvious implementation of each is wrong:

* **A duplicate is answered 200 with `deduplicated: true`.** Not 409, not 400. A producer reads
  a non-2xx as "that failed" and retries harder — answering a retry with an error is how you
  turn one duplicate into a storm.
* **An event with no sinks is still stored.** "Understood, nothing to do" is an outcome worth
  being able to look up later.
* **Retry backoff is jittered.** After an outage every queued delivery becomes due at the same
  instant; without jitter they all fire together and re-create the outage they were waiting on.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import random
from datetime import timedelta
from typing import Any

import httpx
import structlog

from . import tracing
from .config import Config
from .errors import PermanentSinkError, SinkError
from .metrics import METRICS
from .models import Delivery, DlqEntry, InboundEvent, StoredEvent, utcnow
from .redaction import redact_text
from .secrets import Resolved
from .sinks import Sink, build_sink
from .store import SqliteStore, Store

log = structlog.get_logger(__name__)

CLAIM_BATCH = 32


class Engine:
    """Owns the store, the sinks, and the background loops."""

    def __init__(self, resolved: Resolved, store: Store | None = None) -> None:
        self.resolved = resolved
        self.config: Config = resolved.config
        self.store: Store = store or SqliteStore(self.config.storage.path)
        self._sinks: dict[str, Sink] = {}
        self._client: httpx.AsyncClient | None = None
        self._tasks: list[asyncio.Task] = []
        self._stopping = asyncio.Event()

    # -- lifecycle ---------------------------------------------------------------------

    async def start(self) -> None:
        """Connect the store, build sinks, re-queue orphans, and start the loops."""
        await self.store.connect()

        for name, state in self.resolved.sinks.items():
            if not state.enabled:
                # Not built, and not silently skipped either: a delivery routed here will fail
                # permanently and land in the DLQ, which is visible. Dropping it would not be.
                continue
            self._sinks[name] = build_sink(state.config, self.resolved.secrets)

        requeued = await self.store.requeue_incomplete()
        if requeued:
            log.info("startup_requeue", deliveries=requeued)

        self._client = httpx.AsyncClient(
            timeout=self.config.delivery.timeout_seconds,
            follow_redirects=False,
        )
        self._stopping.clear()
        self._tasks = [
            asyncio.create_task(self._delivery_loop(), name="doorman-delivery"),
            asyncio.create_task(self._sweep_loop(), name="doorman-sweep"),
        ]
        log.info("engine_started", sinks=sorted(self._sinks))

    async def stop(self) -> None:
        """Stop the loops and release the store and HTTP client."""
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()

        if self._client is not None:
            await self._client.aclose()
            self._client = None
        await self.store.close()
        log.info("engine_stopped")

    # -- ingest ------------------------------------------------------------------------

    async def ingest(self, event: InboundEvent) -> dict[str, Any]:
        """Persist a verified event and queue its deliveries.

        Returns the JSON body for the producer. Always a 200-shaped response: by the time this
        is called the request has been verified, and everything after that is our problem.
        """
        with tracing.span(
            "ingest",
            source=event.source,
            event_type=event.event_type,
            verified=event.verified,
            # The producer's own id for this delivery. It is the correlation key across the
            # ingest span and the delivery spans, which are not causally linked — a retry runs
            # in a background worker minutes later, under no request context at all.
            delivery_id=event.delivery_id,
        ) as current:
            result = await self._ingest(event)
            if current is not None:
                current.set_attribute("outcome", result["status"])
            return result

    async def _ingest(self, event: InboundEvent) -> dict[str, Any]:
        event_id, duplicate = await self.store.record_event(event)

        if duplicate:
            log.info(
                "event_deduplicated",
                source=event.source,
                delivery_id=event.delivery_id,
                event_id=event_id,
            )
            METRICS.increment("webhook_doorman_events_deduplicated_total", source=event.source)
            return {"status": "ok", "deduplicated": True, "event_id": event_id}

        # Counted here rather than at either log line below, because both of them are a stored
        # event: one with sinks and one without. Splitting it would make
        # `events_received_total` mean "events that had somewhere to go", which is a different
        # question and already answerable from `delivery_attempts_total`.
        METRICS.increment("webhook_doorman_events_received_total", source=event.source)

        if not event.sinks:
            log.info("event_stored_no_sinks", source=event.source, event_type=event.event_type)
            return {"status": "ignored", "event_id": event_id}

        await self.store.enqueue_deliveries(event_id, event.sinks)
        log.info(
            "event_accepted",
            source=event.source,
            event_type=event.event_type,
            event_id=event_id,
            sinks=event.sinks,
        )
        return {"status": "accepted", "event_id": event_id}

    async def replay(self, event_id: int) -> dict[str, Any]:
        """Re-queue every delivery for a stored event.

        Raises:
            LookupError: no such event.
        """
        event = await self.store.get_event(event_id)
        if event is None:
            raise LookupError(f"event {event_id} not found")

        source = self.config.source_by_name(event.source)
        sinks = list(source.sinks) if source else []
        if not sinks:
            return {"status": "no_sinks", "event_id": event_id}

        await self.store.enqueue_deliveries(event_id, sinks)
        log.warning("event_replayed", event_id=event_id, source=event.source, sinks=sinks)
        return {"status": "replayed", "event_id": event_id, "sinks": sinks}

    async def stats(self) -> dict[str, int]:
        return await self.store.stats()

    async def list_dlq(self, *, limit: int, before_id: int | None = None) -> list[DlqEntry]:
        """Dead-lettered deliveries, newest first. The clamp on `limit` belongs to the caller."""
        return await self.store.list_dlq(limit=limit, before_id=before_id)

    # -- delivery ----------------------------------------------------------------------

    async def _delivery_loop(self) -> None:
        interval = self.config.delivery.poll_interval_seconds
        while not self._stopping.is_set():
            try:
                processed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - the loop must outlive any single failure
                log.exception("delivery_loop_error")
                processed = 0
            if processed == 0:
                await asyncio.sleep(interval)

    async def run_once(self) -> int:
        """Claim and process one batch of due deliveries. Returns how many were processed.

        Exposed so tests can drive the engine deterministically instead of racing a sleep.
        """
        due = await self.store.claim_due_deliveries(utcnow(), CLAIM_BATCH)
        if not due:
            return 0
        await asyncio.gather(*(self._deliver(d) for d in due), return_exceptions=True)
        return len(due)

    async def _deliver(self, delivery: Delivery) -> None:
        # A root span, not a child of the ingest span. A retry runs in the background worker
        # minutes after the request that produced it has finished, so there is no live context
        # to attach to and pretending otherwise would produce a trace whose duration is mostly
        # backoff. `delivery_id` on both spans is the correlation key instead.
        with tracing.span("deliver", sink=delivery.sink, attempt=delivery.attempt):
            await self._deliver_once(delivery)

    async def _deliver_once(self, delivery: Delivery) -> None:
        event = await self.store.get_event(delivery.event_id)
        if event is None:
            # The event was swept while this delivery was queued. Nothing to send and nothing to
            # retry; record it as terminal so it stops being claimed every poll.
            await self._exhaust(delivery, "event no longer exists", None, 0)
            return

        sink = self._sinks.get(delivery.sink)
        if sink is None:
            await self._exhaust(delivery, f"sink {delivery.sink!r} is not available", None, 0)
            return

        try:
            outcome = await sink.deliver(event.template_context(), self._require_client())
        except PermanentSinkError as exc:
            log.warning(
                "delivery_permanent_failure",
                delivery=delivery.id,
                sink=delivery.sink,
                error=self._redact_error(str(exc)),
            )
            self._observe_latency(delivery.sink, exc.latency_ms)
            METRICS.increment(
                "webhook_doorman_delivery_attempts_total",
                sink=delivery.sink,
                outcome="permanent",
            )
            await self._exhaust(delivery, str(exc), None, 0)
        except SinkError as exc:
            self._observe_latency(delivery.sink, exc.latency_ms)
            await self._schedule_retry(delivery, str(exc), None, 0, retry_after=exc.retry_after)
        except Exception as exc:  # pragma: no cover - defensive; a sink bug is not a lost event
            log.exception("delivery_unexpected_error", delivery=delivery.id, sink=delivery.sink)
            await self._schedule_retry(delivery, repr(exc), None, 0)
        else:
            await self.store.mark_delivered(delivery.id, outcome.response_code, outcome.latency_ms)
            log.info(
                "delivery_ok",
                delivery=delivery.id,
                sink=delivery.sink,
                event_id=event.id,
                code=outcome.response_code,
                latency_ms=outcome.latency_ms,
            )
            self._observe_latency(delivery.sink, outcome.latency_ms)
            METRICS.increment(
                "webhook_doorman_delivery_attempts_total",
                sink=delivery.sink,
                outcome="delivered",
            )

    @staticmethod
    def _observe_latency(sink: str, latency_ms: int) -> None:
        """Feed the histogram, converting to the seconds Prometheus convention expects.

        `latency_ms` is milliseconds everywhere else in this codebase — the store column, the
        log line and `DeliveryOutcome` all use it — but the metric is
        `..._latency_seconds`, because base units are the convention and a scraper's alert
        thresholds are written against them.
        """
        METRICS.observe_latency(latency_ms / 1000.0, sink=sink)

    async def _schedule_retry(
        self,
        delivery: Delivery,
        error: str,
        code: int | None,
        latency_ms: int,
        *,
        retry_after: float | None = None,
    ) -> None:
        error = self._redact_error(error)
        attempts_made = delivery.attempt + 1
        if attempts_made >= self.config.delivery.max_attempts:
            log.warning(
                "delivery_exhausted",
                delivery=delivery.id,
                sink=delivery.sink,
                attempts=attempts_made,
                error=error,
            )
            METRICS.increment(
                "webhook_doorman_delivery_attempts_total",
                sink=delivery.sink,
                outcome="exhausted",
            )
            await self._exhaust(delivery, error, code, latency_ms)
            return

        METRICS.increment(
            "webhook_doorman_delivery_attempts_total", sink=delivery.sink, outcome="retry"
        )
        delay = self.retry_delay_seconds(attempts_made, retry_after)
        await self.store.mark_retry(
            delivery.id,
            error=error,
            response_code=code,
            latency_ms=latency_ms,
            next_attempt_at=utcnow() + timedelta(seconds=delay),
        )
        log.info(
            "delivery_retry_scheduled",
            delivery=delivery.id,
            sink=delivery.sink,
            attempt=attempts_made,
            retry_in_s=round(delay, 2),
            honoured_retry_after=retry_after is not None,
            error=error,
        )

    def _redact_error(self, error: str) -> str:
        """Strip resolved secrets from a delivery error before it is persisted or logged.

        `redaction.py` runs at the *ingest* boundary — it covers what a producer sent us. It has
        never covered what a *destination* sent back, and `HttpSinkBase._send` puts part of that
        response body into the error message. A destination that echoes a submitted credential
        into its 400 page therefore writes that credential into the DLQ verbatim, where it
        survives every backup of the SQLite file.

        This runs at the engine boundary rather than inside the sink deliberately: `sinks/base.py`
        has no business knowing about resolved secrets, and `ARCHITECTURE.md` requires that
        `redaction.py` not know about sinks. Redacting here keeps both true. It is idempotent, so
        the two store-writing paths can each apply it without coordinating.
        """
        return redact_text(error, self.resolved.secret_values)

    async def _exhaust(
        self, delivery: Delivery, error: str, code: int | None, latency_ms: int
    ) -> None:
        await self.store.mark_exhausted(
            delivery.id,
            error=self._redact_error(error),
            response_code=code,
            latency_ms=latency_ms,
            exhausted_at=utcnow(),
        )

    def retry_delay_seconds(self, attempt: int, retry_after: float | None = None) -> float:
        """How long before the next attempt.

        A destination that sent `Retry-After` gets to overrule the backoff curve — it knows when
        its rate-limit window reopens and the curve is only guessing. Discord rate-limits at
        roughly 5 requests / 2 seconds per webhook and Slack at roughly 1 message / second per
        channel, so this is the ordinary case for those, not an exotic one.

        Two things it does not get to do:

        * **Park a delivery.** The value is clamped to `delivery.max_backoff_seconds`. Without
          that, a hostile or buggy destination answering `Retry-After: 86400` holds a delivery
          for a day, and because it never exhausts its attempts the DLQ never sees it either.
        * **Escape the jitter.** A server-supplied delay causes a thundering herd in exactly the
          way an un-jittered backoff does — more so, because every queued delivery for that
          destination gets handed the *same* number rather than merely a similar one.
        """
        cfg = self.config.delivery
        if retry_after is None:
            raw = cfg.base_backoff_seconds * (2 ** max(0, attempt - 1))
        else:
            raw = max(0.0, retry_after)
        return _jittered(min(raw, cfg.max_backoff_seconds), cfg.jitter)

    def backoff_seconds(self, attempt: int) -> float:
        """Exponential backoff with jitter, capped.

        Jitter is not decoration. After an outage every queued delivery comes due at the same
        moment; firing them in lockstep re-creates the load that caused the outage.
        """
        return self.retry_delay_seconds(attempt)

    # -- retention ---------------------------------------------------------------------

    async def _sweep_loop(self) -> None:
        interval = self.config.storage.sweep_interval_seconds
        while not self._stopping.is_set():
            await asyncio.sleep(interval)
            if self._stopping.is_set():
                return
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover
                log.exception("sweep_error")

    async def sweep_once(self) -> tuple[int, int]:
        now = utcnow()
        return await self.store.sweep(
            events_before=now - timedelta(days=self.config.storage.retention_days),
            dlq_before=now - timedelta(days=self.config.storage.dlq_retention_days),
        )

    # -- internals ---------------------------------------------------------------------

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("engine is not started")
        return self._client

    def check_admin_token(self, presented: str) -> bool:
        """Constant-time check of the replay credential.

        Returns False when replay is disabled, so a missing token can never be an open door.
        """
        expected = self.resolved.admin_token()
        if not expected or not presented:
            return False
        return hmac.compare_digest(expected, presented)


def _jittered(seconds: float, jitter: float) -> float:
    """Spread a delay by ±`jitter` of itself, never below zero."""
    spread = seconds * jitter
    return max(0.0, seconds + random.uniform(-spread, spread))


def stored_event_context(event: StoredEvent) -> dict[str, Any]:
    """Template namespace for a stored event. Thin, but it keeps `StoredEvent` out of sinks."""
    return event.template_context()
