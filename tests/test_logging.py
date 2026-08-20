"""Log configuration and request-scoped context.

Two things are being pinned down here, and neither is cosmetic:

* **`merge_contextvars` is wired in.** Every `bind_contextvars` call in this package is a silent
  no-op without it — the binding succeeds, the log line simply does not carry it. That failure
  looks exactly like working code right up until someone needs to correlate a 401.
* **The context does not leak between requests.** A contextvar left bound in an async handler
  attaches one request's ids to another's lines, which is worse than having no ids at all.
"""

from __future__ import annotations

import asyncio
import json
import logging as stdlib_logging

import pytest
import structlog
from fastapi.testclient import TestClient

from webhook_doorman import app as app_module
from webhook_doorman.app import create_app
from webhook_doorman.config import Config
from webhook_doorman.logging import configure_logging

from .conftest import BEARER_SECRET, GITHUB_SECRET
from .test_app import build, github_headers

BODY = b'{"action": "opened"}'


def build_log_only(config_data: dict, env: dict) -> TestClient:
    """An app on the default `_log_only_ingest`, which is what emits `event_accepted`.

    `test_app.build` supplies its own `ingest`, so it never reaches the logging path.
    """
    app = create_app(config=Config.model_validate(config_data), env=env)
    return TestClient(app, client=("127.0.0.1", 51234))


@pytest.fixture(autouse=True)
def restore_structlog():
    """Structlog config is global. Snapshot it so one test cannot configure another's."""
    saved = structlog.get_config()
    try:
        yield
    finally:
        structlog.configure(**saved)


@pytest.fixture
def captured(monkeypatch) -> list[dict]:
    """Capture log lines *through* the real contextvars processor.

    `structlog.testing.capture_logs` is not usable here: it replaces the whole processor chain,
    which drops `merge_contextvars` — the one thing under test.

    The `log` rebind is not optional. `configure_logging` sets `cache_logger_on_first_use`, and
    the first call through a lazy proxy under that setting makes the proxy *become* the bound
    logger permanently. Any earlier test in the session that configured logging has therefore
    already frozen `app.log` against the old processor chain, and reconfiguring here would do
    nothing to it. That is invisible in isolation and only shows up in a full run.
    """
    entries: list[dict] = []

    def capture(_logger, _name, event_dict):
        entries.append(dict(event_dict))
        raise structlog.DropEvent

    structlog.configure(
        processors=[structlog.contextvars.merge_contextvars, capture],
        wrapper_class=structlog.make_filtering_bound_logger(stdlib_logging.DEBUG),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    monkeypatch.setattr(app_module, "log", structlog.get_logger("webhook_doorman.app"))
    return entries


def renderer():
    """The last processor in the configured chain — whichever renderer was selected."""
    return structlog.get_config()["processors"][-1]


class TestLogFormat:
    def test_json_is_the_default(self):
        configure_logging()
        assert isinstance(renderer(), structlog.processors.JSONRenderer)

    def test_console_is_opt_in_by_argument(self):
        configure_logging(log_format="console")
        assert isinstance(renderer(), structlog.dev.ConsoleRenderer)

    def test_console_is_opt_in_by_environment(self, monkeypatch):
        monkeypatch.setenv("LOG_FORMAT", "console")
        configure_logging()
        assert isinstance(renderer(), structlog.dev.ConsoleRenderer)

    def test_an_unknown_format_falls_back_to_json(self, monkeypatch):
        """A typo in a container's environment must not silently change the log format."""
        monkeypatch.setenv("LOG_FORMAT", "yaml-please")
        configure_logging()
        assert isinstance(renderer(), structlog.processors.JSONRenderer)

    def test_the_argument_beats_the_environment(self, monkeypatch):
        monkeypatch.setenv("LOG_FORMAT", "console")
        configure_logging(log_format="json")
        assert isinstance(renderer(), structlog.processors.JSONRenderer)

    def test_contextvars_are_merged_first(self):
        """Anywhere but first and a processor ahead of it renders a line without the context."""
        configure_logging()
        assert structlog.get_config()["processors"][0] is structlog.contextvars.merge_contextvars

    def test_json_output_is_parseable(self, capsys):
        configure_logging()
        structlog.get_logger("probe").warning("some_event", detail="x")
        assert json.loads(capsys.readouterr().out)["event"] == "some_event"


class TestRequestContext:
    def find(self, captured: list[dict], event: str) -> dict:
        matches = [e for e in captured if e.get("event") == event]
        assert matches, f"no {event!r} line in {[e.get('event') for e in captured]}"
        return matches[0]

    def test_a_401_carries_the_source(self, base_config, base_env, captured):
        """Before this, `verification_failed` named a source and nothing else — a rejection that
        could not be correlated with the request that caused it."""
        client = build(base_config, base_env)
        response = client.post(
            "/webhook/internal", content=BODY, headers={"Authorization": "Bearer wrong"}
        )
        assert response.status_code == 401
        assert self.find(captured, "verification_failed")["source"] == "internal"

    def test_a_413_carries_the_source(self, base_config, base_env, captured):
        client = build(base_config, base_env)
        response = client.post(
            "/webhook/internal",
            content=b"x" * 5000,
            headers={"Authorization": f"Bearer {BEARER_SECRET}"},
        )
        assert response.status_code == 413
        assert self.find(captured, "body_too_large")["source"] == "internal"

    def test_a_disabled_source_rejection_carries_the_source(self, base_config, base_env, captured):
        del base_env["GITHUB_WEBHOOK_SECRET"]
        client = build(base_config, base_env)
        assert client.post("/webhook/github", content=BODY).status_code == 503
        assert self.find(captured, "source_disabled_rejected")["source"] == "github"

    def test_an_accepted_event_carries_the_delivery_id(self, base_config, base_env, captured):
        client = build_log_only(base_config, base_env)
        body = json.dumps({"action": "opened", "repository": {"full_name": "o/r"}}).encode()
        response = client.post(
            "/webhook/github", content=body, headers=github_headers(body, "delivery-abc")
        )
        assert response.status_code == 200
        assert self.find(captured, "event_accepted")["delivery_id"] == "delivery-abc"

    def test_a_401_carries_no_delivery_id(self, base_config, base_env, captured):
        """It is not known yet at that point, and inventing one would be worse than omitting it."""
        client = build(base_config, base_env)
        client.post("/webhook/internal", content=BODY, headers={"Authorization": "Bearer wrong"})
        assert "delivery_id" not in self.find(captured, "verification_failed")

    def test_the_context_is_cleared_after_the_request(self, base_config, base_env, captured):
        """A leaked binding attaches this request's ids to whatever logs next."""
        client = build(base_config, base_env)
        client.post("/webhook/internal", content=BODY, headers={"Authorization": "Bearer wrong"})
        assert structlog.contextvars.get_contextvars() == {}

    def test_an_outer_binding_survives_the_request(self, base_config, base_env, captured):
        """`bound_contextvars` restores rather than clears — a caller's own context is not ours
        to discard, and a bare `clear_contextvars()` in the handler would discard it."""
        client = build(base_config, base_env)
        with structlog.contextvars.bound_contextvars(run_id="outer-42"):
            client.post(
                "/webhook/internal", content=BODY, headers={"Authorization": "Bearer wrong"}
            )
            assert structlog.contextvars.get_contextvars() == {"run_id": "outer-42"}

    async def test_concurrent_requests_do_not_cross_contaminate(
        self, base_config, base_env, captured
    ):
        """The failure this guards against is invisible in a serial suite: ids from one request
        appearing on another's lines only shows up once two are genuinely in flight together.
        """
        client = build_log_only(base_config, base_env)

        def post(delivery: str) -> None:
            body = json.dumps({"action": "opened", "delivery": delivery}).encode()
            client.post("/webhook/github", content=body, headers=github_headers(body, delivery))

        await asyncio.gather(
            *(asyncio.to_thread(post, f"delivery-{i}") for i in range(8)),
        )

        accepted = [e for e in captured if e.get("event") == "event_accepted"]
        assert len(accepted) == 8
        # Each id reaches the line only through the contextvar — `_log_only_ingest` does not
        # pass it — so eight distinct ids is eight uncrossed contexts.
        assert {e["delivery_id"] for e in accepted} == {f"delivery-{i}" for i in range(8)}
        assert all(e["source"] == "github" for e in accepted)

    def test_the_context_does_not_carry_a_secret(self, base_config, base_env, captured):
        client = build(base_config, base_env)
        client.post("/webhook/internal", content=BODY, headers={"Authorization": "Bearer wrong"})
        blob = json.dumps(captured)
        assert GITHUB_SECRET not in blob
        assert BEARER_SECRET not in blob
