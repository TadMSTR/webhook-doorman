"""The delivery engine: dedup responses, retry, DLQ, replay.

These tests drive `run_once()` directly rather than waiting on the background loop. Racing a
sleep produces a suite that is slow when it passes and confusing when it fails.
"""

from __future__ import annotations

from datetime import datetime

import httpx
import pytest

from webhook_doorman.config import Config
from webhook_doorman.engine import Engine
from webhook_doorman.errors import PermanentSinkError, SinkError
from webhook_doorman.models import InboundEvent, utcnow
from webhook_doorman.secrets import resolve
from webhook_doorman.store import SqliteStore

SINK_URL = "https://sink.example.invalid/notes"

# poll_interval is deliberately enormous. These tests drive delivery through `run_once()` so
# they are deterministic; a live background loop on a short tick competes for the same rows and
# turns every assertion into a race the suite wins locally and loses on a slower CI runner.
# The loop still runs one empty claim at startup, which is harmless.
CONFIG: dict = {
    "delivery": {"max_attempts": 3, "base_backoff_seconds": 1, "poll_interval_seconds": 3600},
    "sources": [
        {
            "name": "internal",
            "path": "/webhook/internal",
            "verify": {"strategy": "bearer", "secret_env": "INTERNAL_TOKEN"},
            "sinks": ["notes"],
        }
    ],
    "sinks": [
        {
            "name": "notes",
            "type": "http",
            "url": SINK_URL,
            "template": '{"text": "{{ summary }}"}',
        }
    ],
}

ENV = {"INTERNAL_TOKEN": "internal-token-0123456789abcdef"}


@pytest.fixture
async def engine(tmp_path):
    config = Config.model_validate(CONFIG)
    resolved = resolve(config, ENV)
    eng = Engine(resolved, store=SqliteStore(tmp_path / "engine.db"))
    await eng.start()
    yield eng
    await eng.stop()


async def next_attempt_delay(engine: Engine) -> float:
    """Seconds from now until the one pending delivery is next due.

    Read from the row rather than from the return value of a helper, because the thing under
    test is what the *scheduler wrote down* — a delay computed correctly and then stored against
    the wrong column would pass any assertion made on the computation alone.
    """
    cursor = await engine.store.db.execute(
        "SELECT next_attempt_at FROM deliveries WHERE next_attempt_at IS NOT NULL"
    )
    row = await cursor.fetchone()
    assert row is not None, "no delivery was scheduled for a retry"
    return (datetime.fromisoformat(row["next_attempt_at"]) - utcnow()).total_seconds()


def event(delivery_id: str = "d-1", sinks: list[str] | None = None) -> InboundEvent:
    return InboundEvent(
        source="internal",
        delivery_id=delivery_id,
        event_type="ping",
        summary="a summary",
        headers={},
        body=b'{"ok": true}',
        payload={"ok": True},
        sinks=["notes"] if sinks is None else sinks,
    )


class TestIngest:
    async def test_first_delivery_is_accepted(self, engine):
        result = await engine.ingest(event())
        assert result["status"] == "accepted"
        assert result["event_id"] > 0

    async def test_duplicate_returns_200_shaped_dedup_not_an_error(self, engine):
        """GitHub marks a non-2xx delivery failed and retries harder. A duplicate is a success."""
        first = await engine.ingest(event("same"))
        second = await engine.ingest(event("same"))
        assert second["deduplicated"] is True
        assert second["status"] == "ok"
        assert second["event_id"] == first["event_id"]

    async def test_a_duplicate_creates_no_extra_deliveries(self, engine):
        await engine.ingest(event("same"))
        await engine.ingest(event("same"))
        assert (await engine.stats())["deliveries"] == 1

    async def test_an_event_with_no_sinks_is_stored_and_ignored(self, engine):
        result = await engine.ingest(event(sinks=[]))
        assert result["status"] == "ignored"
        stats = await engine.stats()
        assert stats["events"] == 1
        assert stats["deliveries"] == 0


class TestDelivery:
    async def test_successful_delivery_is_marked_delivered(self, engine, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        await engine.ingest(event())
        assert await engine.run_once() == 1
        assert (await engine.stats())["deliveries_delivered"] == 1

    async def test_the_rendered_template_reaches_the_sink(self, engine, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        await engine.ingest(event())
        await engine.run_once()
        request = httpx_mock.get_requests()[0]
        assert request.read() == b'{"text": "a summary"}'

    async def test_a_5xx_is_retried_not_dropped(self, engine, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=503)
        await engine.ingest(event())
        await engine.run_once()
        stats = await engine.stats()
        assert stats.get("deliveries_pending") == 1
        assert stats.get("deliveries_exhausted", 0) == 0

    async def test_a_4xx_goes_straight_to_the_dlq(self, engine, httpx_mock):
        """Retrying a 400 five times only delays the moment the operator finds out."""
        httpx_mock.add_response(url=SINK_URL, status_code=400)
        await engine.ingest(event())
        await engine.run_once()
        stats = await engine.stats()
        assert stats["dlq"] == 1
        assert stats["deliveries_exhausted"] == 1

    @pytest.mark.parametrize("code", [408, 429])
    async def test_retryable_4xx_codes_are_retried(self, engine, httpx_mock, code):
        """408 and 429 are the server explicitly asking you to try again."""
        httpx_mock.add_response(url=SINK_URL, status_code=code)
        await engine.ingest(event())
        await engine.run_once()
        assert (await engine.stats()).get("deliveries_pending") == 1

    async def test_a_timeout_is_retried(self, engine, httpx_mock):
        httpx_mock.add_exception(httpx.ReadTimeout("too slow"), url=SINK_URL)
        await engine.ingest(event())
        await engine.run_once()
        assert (await engine.stats()).get("deliveries_pending") == 1

    async def test_a_down_sink_dlqs_after_max_attempts_rather_than_dropping(
        self, engine, httpx_mock
    ):
        httpx_mock.add_response(url=SINK_URL, status_code=500, is_reusable=True)
        await engine.ingest(event())
        for _ in range(CONFIG["delivery"]["max_attempts"]):
            await engine.store.requeue_incomplete()  # collapse the backoff window
            await engine.run_once()
        stats = await engine.stats()
        assert stats["dlq"] == 1
        assert stats["deliveries_exhausted"] == 1

    async def test_a_delivery_to_an_unavailable_sink_is_recorded_not_dropped(self, tmp_path):
        """A disabled sink must produce a visible DLQ entry, not a silent no-op."""
        data = dict(CONFIG)
        data = Config.model_validate(
            {
                **CONFIG,
                "sinks": [
                    {
                        "name": "notes",
                        "type": "matrix",
                        "url": "https://matrix.example.invalid",
                        "token_env": "MATRIX_TOKEN",
                        "room_env": "MATRIX_ROOM",
                    }
                ],
            }
        )
        eng = Engine(resolve(data, ENV), store=SqliteStore(tmp_path / "disabled.db"))
        await eng.start()
        try:
            await eng.ingest(event())
            await eng.run_once()
            assert (await eng.stats())["dlq"] == 1
        finally:
            await eng.stop()

    async def test_run_once_reports_zero_when_nothing_is_due(self, engine):
        assert await engine.run_once() == 0


class TestBackoff:
    def test_grows_exponentially(self, engine):
        engine.config.delivery.jitter = 0.0
        assert engine.backoff_seconds(1) == 1
        assert engine.backoff_seconds(2) == 2
        assert engine.backoff_seconds(3) == 4

    def test_is_capped(self, engine):
        engine.config.delivery.jitter = 0.0
        engine.config.delivery.max_backoff_seconds = 5
        assert engine.backoff_seconds(20) == 5

    def test_jitter_spreads_a_thundering_herd(self, engine):
        """Without jitter every delivery queued during an outage fires at the same instant."""
        engine.config.delivery.jitter = 0.5
        values = {engine.backoff_seconds(3) for _ in range(50)}
        assert len(values) > 1
        assert all(2 <= v <= 6 for v in values)

    def test_never_negative(self, engine):
        engine.config.delivery.jitter = 2.0
        assert all(engine.backoff_seconds(1) >= 0 for _ in range(50))


class TestRetryAfter:
    """A destination's own answer about when to come back, and the bounds on trusting it."""

    def test_overrides_the_backoff_curve(self, engine):
        engine.config.delivery.jitter = 0.0
        assert engine.backoff_seconds(1) == 1  # what the curve would have chosen
        assert engine.retry_delay_seconds(1, 7.0) == 7.0

    def test_is_clamped_to_max_backoff(self, engine):
        """`Retry-After: 86400` would park the delivery for a day, and because it never runs out
        of attempts the DLQ would never see it either."""
        engine.config.delivery.jitter = 0.0
        engine.config.delivery.max_backoff_seconds = 300
        assert engine.retry_delay_seconds(1, 86400.0) == 300

    def test_still_jitters(self, engine):
        """Every queued delivery for one destination is handed the same number, so honouring it
        to the millisecond is a thundering herd by construction."""
        engine.config.delivery.jitter = 0.5
        values = {engine.retry_delay_seconds(1, 8.0) for _ in range(50)}
        assert len(values) > 1
        assert all(4 <= v <= 12 for v in values)

    def test_a_negative_value_never_becomes_a_negative_delay(self, engine):
        engine.config.delivery.jitter = 0.0
        assert engine.retry_delay_seconds(1, -30.0) == 0.0

    def test_none_falls_back_to_the_curve(self, engine):
        engine.config.delivery.jitter = 0.0
        assert engine.retry_delay_seconds(3, None) == engine.backoff_seconds(3)

    async def test_a_429_schedules_at_the_advertised_delay(self, engine, httpx_mock):
        """End to end: response header -> `SinkError.retry_after` -> `next_attempt_at`."""
        engine.config.delivery.jitter = 0.0
        httpx_mock.add_response(url=SINK_URL, status_code=429, headers={"Retry-After": "7"})
        await engine.ingest(event())
        await engine.run_once()

        delay = await next_attempt_delay(engine)
        assert 6 <= delay <= 8  # not the ~1s the exponential curve would have picked

    async def test_without_the_header_the_curve_still_applies(self, engine, httpx_mock):
        engine.config.delivery.jitter = 0.0
        httpx_mock.add_response(url=SINK_URL, status_code=429)
        await engine.ingest(event())
        await engine.run_once()

        assert await next_attempt_delay(engine) <= 2  # base_backoff_seconds is 1 here

    async def test_a_hostile_delay_cannot_park_a_delivery(self, engine, httpx_mock):
        engine.config.delivery.jitter = 0.0
        engine.config.delivery.max_backoff_seconds = 5
        httpx_mock.add_response(url=SINK_URL, status_code=429, headers={"Retry-After": "86400"})
        await engine.ingest(event())
        await engine.run_once()

        assert await next_attempt_delay(engine) <= 6


class TestUnicodeFailsFast:
    async def test_an_unencodable_header_dlqs_on_the_first_attempt(self, tmp_path, httpx_mock):
        """One attempt and a DLQ row, not `max_attempts` of a failure that cannot change.

        Driven through the generic `http` sink with a non-ASCII configured header, so the error
        is raised from inside `client.request` exactly as the live ntfy defect raised it.
        """
        config = Config.model_validate(
            {
                **CONFIG,
                "sinks": [
                    {
                        "name": "notes",
                        "type": "http",
                        "url": SINK_URL,
                        "headers": {"X-Trace": "café"},
                    }
                ],
            }
        )
        eng = Engine(resolve(config, ENV), store=SqliteStore(tmp_path / "unicode.db"))
        await eng.start()
        try:
            await eng.ingest(event())
            await eng.run_once()
            stats = await eng.stats()
            assert stats["dlq"] == 1
            assert stats["deliveries_exhausted"] == 1
            assert stats.get("deliveries_pending", 0) == 0
            assert httpx_mock.get_requests() == []
        finally:
            await eng.stop()


class TestReplay:
    async def test_replay_requeues_the_deliveries(self, engine, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200, is_reusable=True)
        result = await engine.ingest(event())
        await engine.run_once()

        replayed = await engine.replay(result["event_id"])
        assert replayed["status"] == "replayed"
        assert await engine.run_once() == 1

    async def test_replaying_an_unknown_event_raises(self, engine):
        with pytest.raises(LookupError):
            await engine.replay(9999)


class TestAdminToken:
    async def test_rejects_when_replay_is_disabled(self, engine):
        assert engine.check_admin_token("anything") is False

    async def test_rejects_an_empty_presented_token(self, tmp_path):
        config = Config.model_validate({**CONFIG, "admin": {"token_env": "ADMIN_TOKEN"}})
        eng = Engine(resolve(config, {**ENV, "ADMIN_TOKEN": "a" * 32}))
        assert eng.check_admin_token("") is False

    async def test_accepts_the_configured_token(self, tmp_path):
        config = Config.model_validate({**CONFIG, "admin": {"token_env": "ADMIN_TOKEN"}})
        eng = Engine(resolve(config, {**ENV, "ADMIN_TOKEN": "a" * 32}))
        assert eng.check_admin_token("a" * 32) is True
        assert eng.check_admin_token("b" * 32) is False


class TestErrorTaxonomy:
    def test_permanent_is_a_sink_error(self):
        """The engine catches PermanentSinkError first; if the hierarchy inverted, a permanent
        failure would silently become a retry."""
        assert issubclass(PermanentSinkError, SinkError)
