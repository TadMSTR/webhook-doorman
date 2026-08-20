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

from .config import Config
from .errors import PermanentSinkError, SinkError
from .models import Delivery, InboundEvent, StoredEvent, utcnow
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
        event_id, duplicate = await self.store.record_event(event)

        if duplicate:
            log.info(
                "event_deduplicated",
                source=event.source,
                delivery_id=event.delivery_id,
                event_id=event_id,
            )
            return {"status": "ok", "deduplicated": True, "event_id": event_id}

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
                error=str(exc),
            )
            await self._exhaust(delivery, str(exc), None, 0)
        except SinkError as exc:
            await self._schedule_retry(delivery, str(exc), None, 0)
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

    async def _schedule_retry(
        self, delivery: Delivery, error: str, code: int | None, latency_ms: int
    ) -> None:
        attempts_made = delivery.attempt + 1
        if attempts_made >= self.config.delivery.max_attempts:
            log.warning(
                "delivery_exhausted",
                delivery=delivery.id,
                sink=delivery.sink,
                attempts=attempts_made,
                error=error,
            )
            await self._exhaust(delivery, error, code, latency_ms)
            return

        delay = self.backoff_seconds(attempts_made)
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
            error=error,
        )

    async def _exhaust(
        self, delivery: Delivery, error: str, code: int | None, latency_ms: int
    ) -> None:
        await self.store.mark_exhausted(
            delivery.id,
            error=error,
            response_code=code,
            latency_ms=latency_ms,
            exhausted_at=utcnow(),
        )

    def backoff_seconds(self, attempt: int) -> float:
        """Exponential backoff with jitter, capped.

        Jitter is not decoration. After an outage every queued delivery comes due at the same
        moment; firing them in lockstep re-creates the load that caused the outage.
        """
        cfg = self.config.delivery
        raw = cfg.base_backoff_seconds * (2 ** max(0, attempt - 1))
        capped = min(raw, cfg.max_backoff_seconds)
        spread = capped * cfg.jitter
        return max(0.0, capped + random.uniform(-spread, spread))

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


def stored_event_context(event: StoredEvent) -> dict[str, Any]:
    """Template namespace for a stored event. Thin, but it keeps `StoredEvent` out of sinks."""
    return event.template_context()
