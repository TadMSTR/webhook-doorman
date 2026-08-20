"""Metrics: the exposition format, the counter/gauge distinction, and label cardinality.

`metrics.py` emits the Prometheus text format by hand rather than depending on
`prometheus_client`. That makes "the output is valid exposition" a claim this file has to
*check* rather than assert — a hand-written assertion agreeing with a hand-written emitter
proves nothing. So the parser from `prometheus_client` is a **test-only** dependency and every
rendering test runs the real output through it.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from webhook_doorman.app import create_app
from webhook_doorman.config import Config
from webhook_doorman.engine import Engine
from webhook_doorman.metrics import METRICS, Metrics
from webhook_doorman.secrets import resolve
from webhook_doorman.store import SqliteStore

from .conftest import GITHUB_SECRET, sign_hex

SINK_URL = "https://sink.example.invalid/notes"
METRICS_TOKEN = "metrics-token-for-tests-0123456789ab"

BODY = json.dumps(
    {
        "action": "opened",
        "issue": {"number": 7, "title": "Something broke", "user": {"login": "octocat"}},
        "repository": {"full_name": "o/r"},
    }
).encode()


def config_data(**overrides) -> dict:
    return {
        "delivery": {"max_attempts": 2, "poll_interval_seconds": 3600},
        "sources": [
            {
                "name": "github",
                "path": "/webhook/github",
                "parser": "github",
                "verify": {
                    "strategy": "hmac_sha256",
                    "header": "X-Hub-Signature-256",
                    "prefix": "sha256=",
                    "secret_env": "GITHUB_WEBHOOK_SECRET",
                },
                "dedup": {"id_header": "X-GitHub-Delivery"},
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
        **overrides,
    }


ENV = {"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET, "METRICS_TOKEN": METRICS_TOKEN}


@pytest.fixture(autouse=True)
def clean_metrics():
    """`METRICS` is process-wide, so counters would otherwise leak between tests."""
    METRICS.reset()
    yield
    METRICS.reset()


@pytest.fixture
def stack(tmp_path):
    resolved = resolve(Config.model_validate(config_data()), ENV)
    engine = Engine(resolved, store=SqliteStore(tmp_path / "doorman.db"))
    app = create_app(resolved=resolved, engine=engine)
    with TestClient(app, client=("127.0.0.1", 51234)) as client:
        yield client, engine


def headers(body: bytes = BODY, delivery: str = "m-1") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, body, "sha256="),
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
    }


def scrape(client: TestClient) -> str:
    response = client.get("/metrics")
    assert response.status_code == 200
    return response.text


def families(text: str):
    return {f.name: f for f in text_string_to_metric_families(text)}


def sample(text: str, name: str, **labels) -> float:
    """One sample's value, matched by name and exact labels."""
    for family in text_string_to_metric_families(text):
        for s in family.samples:
            if s.name == name and s.labels == labels:
                return s.value
    raise AssertionError(f"no sample {name}{labels} in:\n{text}")


def run_batch(client: TestClient, engine: Engine) -> int:
    return client.portal.call(engine.run_once)


class TestExpositionFormat:
    def test_the_output_parses_as_prometheus_exposition(self, stack):
        """Checked with the reference parser, not with a regex of my own devising."""
        client, _ = stack
        assert families(scrape(client))

    def test_a_sink_name_containing_a_quote_does_not_break_the_scrape(self):
        """Label values are the one place operator text reaches the output.

        A broken line here is not an error anyone sees — it is a scrape target that silently
        stops parsing.
        """
        metrics = Metrics()
        metrics.increment("webhook_doorman_delivery_attempts_total", sink='say "hi"', outcome="x")
        text = metrics.render(version="0.0.0")

        # The reference parser is the assertion: it round-trips the escaped value back to the
        # original, which a regex over the escaped form would not actually prove.
        labels = [
            s.labels
            for f in text_string_to_metric_families(text)
            for s in f.samples
            if s.name == "webhook_doorman_delivery_attempts_total"
        ]
        assert labels == [{"sink": 'say "hi"', "outcome": "x"}]

    def test_build_info_carries_the_version(self, stack):
        client, _ = stack
        assert (
            sample(
                scrape(client),
                "webhook_doorman_build_info",
                version=__import__("webhook_doorman").__version__,
            )
            == 1.0
        )

    def test_process_start_time_is_exported(self, stack):
        """A scraper needs it to tell a counter reset from a real drop to zero."""
        client, _ = stack
        assert sample(scrape(client), "process_start_time_seconds") > 0


class TestGaugesAreNotCounters:
    def test_no_gauge_is_named_total(self, stack):
        """The single most common way this endpoint ships subtly broken.

        `store.stats()` returns current table counts, and every one of them goes *down* when
        the retention sweep runs. Named `_total`, Prometheus would read that drop as a counter
        reset and every `rate()` over it would be wrong.
        """
        client, _ = stack
        for name, family in families(scrape(client)).items():
            if family.type == "gauge":
                assert not name.endswith("_total"), f"{name} is a gauge named like a counter"

    def test_no_counter_is_typed_as_a_gauge(self, stack):
        client, _ = stack
        for name, family in families(scrape(client)).items():
            if name.startswith("webhook_doorman_") and name.endswith("_total"):
                assert family.type == "counter"

    def test_table_counts_are_reported_as_gauges(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert sample(text, "webhook_doorman_events_stored") == 1
        assert sample(text, "webhook_doorman_dlq_size") == 0
        assert sample(text, "webhook_doorman_deliveries", status="delivered") == 1


class TestCounters:
    def test_a_rejected_request_increments_verification_failures(self, stack):
        """The rejection rate is the security signal for a fail-closed router."""
        client, _ = stack
        before = sample(
            scrape(client),
            "webhook_doorman_verification_failures_total",
            source="github",
            strategy="hmac_sha256",
        )
        bad = {**headers(), "X-Hub-Signature-256": "sha256=" + "0" * 64}
        assert client.post("/webhook/github", content=BODY, headers=bad).status_code == 401

        assert (
            sample(
                scrape(client),
                "webhook_doorman_verification_failures_total",
                source="github",
                strategy="hmac_sha256",
            )
            == before + 1
        )

    def test_an_oversized_body_increments_the_rejection_counter(self, tmp_path):
        resolved = resolve(Config.model_validate(config_data(server={"max_body_bytes": 10})), ENV)
        engine = Engine(resolved, store=SqliteStore(tmp_path / "d.db"))
        with TestClient(create_app(resolved=resolved, engine=engine)) as client:
            client.post("/webhook/github", content=BODY, headers=headers())
            assert (
                sample(
                    scrape(client),
                    "webhook_doorman_requests_rejected_total",
                    source="github",
                    reason="body_too_large",
                )
                == 1
            )

    def test_a_duplicate_increments_the_dedup_counter(self, stack):
        """No delivery is driven here — dedup is decided at ingest, before any sink is called."""
        client, _ = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        client.post("/webhook/github", content=BODY, headers=headers())

        text = scrape(client)
        assert sample(text, "webhook_doorman_events_received_total", source="github") == 1
        assert sample(text, "webhook_doorman_events_deduplicated_total", source="github") == 1

    def test_a_retryable_failure_increments_outcome_retry(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=503)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert (
            sample(text, "webhook_doorman_delivery_attempts_total", sink="notes", outcome="retry")
            == 1
        )

    def test_a_permanent_failure_increments_outcome_permanent(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=400)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert (
            sample(
                scrape(client),
                "webhook_doorman_delivery_attempts_total",
                sink="notes",
                outcome="permanent",
            )
            == 1
        )

    def test_a_3xx_is_counted_as_permanent_not_delivered(self, stack, httpx_mock):
        """Phase 0's fix, made visible. It used to be silence; now it is a number."""
        httpx_mock.add_response(
            url=SINK_URL, status_code=301, headers={"Location": "https://elsewhere.invalid/"}
        )
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert (
            sample(
                text,
                "webhook_doorman_delivery_attempts_total",
                sink="notes",
                outcome="permanent",
            )
            == 1
        )
        assert (
            sample(
                text,
                "webhook_doorman_delivery_attempts_total",
                sink="notes",
                outcome="delivered",
            )
            == 0
        )

    def test_config_derived_series_exist_before_anything_happens(self, stack):
        """Otherwise "no failures yet" and "target not reporting" look identical to an alert."""
        text = scrape(stack[0])
        for outcome in ("delivered", "retry", "permanent", "exhausted"):
            assert (
                sample(
                    text,
                    "webhook_doorman_delivery_attempts_total",
                    sink="notes",
                    outcome=outcome,
                )
                == 0
            )


class TestLatencyHistogram:
    def test_a_successful_delivery_is_observed(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert sample(text, "webhook_doorman_delivery_latency_seconds_count", sink="notes") == 1
        assert (
            sample(text, "webhook_doorman_delivery_latency_seconds_bucket", sink="notes", le="+Inf")
            == 1
        )

    def test_a_failed_delivery_is_observed_too(self, stack, httpx_mock):
        """The case the histogram exists for.

        A destination that is slow *and* failing is exactly what you want to see, and a
        histogram fed only by successes hides it — the p99 improves as the destination gets
        worse. This is why `SinkError` carries `latency_ms`: a failure has no `DeliveryOutcome`
        to put it on.
        """
        httpx_mock.add_response(url=SINK_URL, status_code=503)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert (
            sample(scrape(client), "webhook_doorman_delivery_latency_seconds_count", sink="notes")
            == 1
        )

    def test_a_transport_failure_records_the_time_it_took_to_fail(self, stack, httpx_mock):
        """A connect failure or a timeout is often the *slowest* thing a sink does.

        Recording it as 0ms would file the worst latencies in the fastest bucket, so the
        histogram would look best precisely when the destination is at its worst.
        """
        httpx_mock.add_exception(httpx.ConnectError("refused"), url=SINK_URL)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert sample(text, "webhook_doorman_delivery_latency_seconds_count", sink="notes") == 1
        # The elapsed time is real, so it is not asserted as an exact value — only that the
        # observation happened and the sum is a sane non-negative number.
        assert sample(text, "webhook_doorman_delivery_latency_seconds_sum", sink="notes") >= 0

    def test_buckets_are_cumulative(self):
        metrics = Metrics()
        metrics.observe_latency(0.3, sink="s")
        text = metrics.render(version="0.0.0")
        values = [
            s.value
            for f in text_string_to_metric_families(text)
            for s in f.samples
            if s.name == "webhook_doorman_delivery_latency_seconds_bucket"
        ]
        assert values == sorted(values), "a cumulative histogram never decreases across buckets"
        assert values[-1] == 1

    def test_sum_and_count_agree_with_the_observations(self):
        metrics = Metrics()
        for seconds in (0.1, 0.2, 0.4):
            metrics.observe_latency(seconds, sink="s")
        text = metrics.render(version="0.0.0")
        assert sample(text, "webhook_doorman_delivery_latency_seconds_count", sink="s") == 3
        assert (
            pytest.approx(sample(text, "webhook_doorman_delivery_latency_seconds_sum", sink="s"))
            == 0.7
        )


class TestCardinality:
    def test_no_producer_controlled_label_is_ever_emitted(self, stack, httpx_mock):
        """`event_type` and `response_code` are unbounded — a producer varying either would
        turn this endpoint into an out-of-memory. High-cardinality detail belongs in the log."""
        httpx_mock.add_response(url=SINK_URL, status_code=418)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        for family in text_string_to_metric_families(scrape(client)):
            for s in family.samples:
                assert "event_type" not in s.labels
                assert "response_code" not in s.labels

    def test_the_scrape_contains_no_payload_content(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        text = scrape(client)
        assert "octocat" not in text
        assert "Something broke" not in text
        assert GITHUB_SECRET not in text


class TestMetricsExposure:
    def test_unauthenticated_by_default(self, stack):
        """The scrape convention. Deliberate, and mitigated at the proxy — see MetricsConfig."""
        client, _ = stack
        assert client.get("/metrics").status_code == 200

    def test_a_configured_token_gates_the_endpoint(self, tmp_path):
        resolved = resolve(
            Config.model_validate(config_data(metrics={"token_env": "METRICS_TOKEN"})), ENV
        )
        engine = Engine(resolved, store=SqliteStore(tmp_path / "d.db"))
        with TestClient(create_app(resolved=resolved, engine=engine)) as client:
            assert client.get("/metrics").status_code == 401
            assert (
                client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
            )
            assert (
                client.get(
                    "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"}
                ).status_code
                == 200
            )

    def test_a_too_short_token_leaves_the_endpoint_open_and_says_so(self, tmp_path, capsys):
        """The one fail-*open* path in the project, so it must be loud rather than silent.

        An operator who set `metrics.token_env` believes /metrics is gated. If the variable is
        unset or too short it is not, and the only visible difference is a scrape that keeps
        working — so the boot warning is the whole mitigation and is asserted here.
        """
        resolved = resolve(
            Config.model_validate(config_data(metrics={"token_env": "METRICS_TOKEN"})),
            {**ENV, "METRICS_TOKEN": "short"},
        )
        engine = Engine(resolved, store=SqliteStore(tmp_path / "d.db"))
        with TestClient(create_app(resolved=resolved, engine=engine)) as client:
            assert client.get("/metrics").status_code == 200
        assert "metrics_unauthenticated" in capsys.readouterr().out

    def test_a_source_path_may_not_shadow_metrics(self):
        """A proxy deny rule on /metrics must not be able to block an ingest path."""
        data = config_data()
        data["sources"][0]["path"] = "/metrics/foo"
        with pytest.raises(ValueError, match="/metrics"):
            Config.model_validate(data)


class TestDegradedScrape:
    def test_a_store_error_serves_counters_without_gauges(self, stack, monkeypatch):
        """A 500 here reads to a scraper as "the target is down", which is less true than
        "the gauges are missing" — and the counters are what an alert usually evaluates."""
        client, engine = stack

        async def boom():
            raise RuntimeError("store is gone")

        monkeypatch.setattr(engine, "stats", boom)
        text = scrape(client)

        assert families(text), "still valid exposition"
        assert "webhook_doorman_events_received_total" in text
        assert "webhook_doorman_events_stored" not in text
