"""Optional OpenTelemetry: mostly the degraded path, because that is the one that ships.

The happy path is easy and is exercised where the `[otel]` extra is installed (CI installs
`.[dev,otel]`). **The path that matters is the other one** — an operator sets
`OTEL_EXPORTER_OTLP_ENDPOINT` on an image or install that does not carry the extra. A router
that refuses to boot there has traded an optional feature for an outage, so that case is
asserted here and it does not depend on the extra's absence to run: it forces the `ImportError`
deterministically, and therefore tests the same thing whether or not OTel is installed.
"""

from __future__ import annotations

import importlib.util
import json
import sys

import pytest
from fastapi.testclient import TestClient

from webhook_doorman import tracing
from webhook_doorman.app import create_app
from webhook_doorman.config import Config
from webhook_doorman.secrets import resolve

from .conftest import GITHUB_SECRET, sign_hex


def _otel_installed() -> bool:
    # `find_spec` on a submodule *raises* when the parent package is absent rather than
    # returning None, so the absent case — which is the common one — needs the guard.
    try:
        return importlib.util.find_spec("opentelemetry.sdk") is not None
    except ModuleNotFoundError:
        return False


OTEL_INSTALLED = _otel_installed()
ENDPOINT = "http://collector.example.invalid:4318"

BODY = json.dumps(
    {
        "action": "opened",
        "issue": {"number": 7, "title": "Something broke", "user": {"login": "octocat"}},
        "repository": {"full_name": "o/r"},
    }
).encode()

CONFIG = {
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
            "sinks": ["notes"],
        }
    ],
    # No engine is built in this file, so nothing is ever delivered — the sink exists only
    # because a source must route somewhere.
    "sinks": [
        {
            "name": "notes",
            "type": "http",
            "url": "https://sink.example.invalid/notes",
            "template": '{"text": "{{ summary }}"}',
        }
    ],
}
ENV = {"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET}


@pytest.fixture(autouse=True)
def clean_tracer():
    tracing.reset()
    yield
    tracing.reset()


@pytest.fixture
def otel_absent(monkeypatch):
    """Force the OTel imports to fail, whether or not the extra is installed.

    `None` in `sys.modules` makes Python raise `ImportError` on import of that name, which is
    exactly the condition an adopter without the extra hits — and simulating it means this test
    keeps testing the degraded path on a machine where OTel *is* present.
    """
    for name in list(sys.modules):
        if name == "opentelemetry" or name.startswith("opentelemetry."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "opentelemetry", None)


def build(env: dict[str, str] | None = None):
    resolved = resolve(Config.model_validate(CONFIG), ENV)
    app = create_app(resolved=resolved)
    if env is not None:
        tracing.configure(app, env=env)
    return app


def post(client: TestClient):
    return client.post(
        "/webhook/github",
        content=BODY,
        headers={
            "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, BODY, "sha256="),
            "X-GitHub-Event": "issues",
            "Content-Type": "application/json",
        },
    )


class TestNotConfigured:
    def test_no_endpoint_means_no_tracing_and_no_noise(self, capsys):
        assert tracing.configure(env={}) is False
        assert tracing.enabled() is False
        assert "tracing" not in capsys.readouterr().out

    def test_a_blank_endpoint_is_treated_as_unset(self):
        assert tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": "   "}) is False

    def test_span_is_a_no_op_when_disabled(self):
        with tracing.span("ingest", source="github") as current:
            assert current is None


class TestExtraMissing:
    """The case that ships to most adopters."""

    def test_the_app_still_serves_traffic(self, otel_absent, capsys):
        app = build()
        assert tracing.configure(app, env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT}) is False
        with TestClient(app) as client:
            assert post(client).status_code == 200

    def test_it_warns_loudly_rather_than_crashing(self, otel_absent, capsys):
        """A silent no-op would leave an operator waiting for spans that never arrive."""
        assert tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT}) is False

        out = capsys.readouterr().out
        assert "tracing_unavailable" in out
        assert "webhook-doorman[otel]" in out, "the warning must say how to fix it"

    def test_spans_stay_no_ops(self, otel_absent):
        tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT})
        assert tracing.enabled() is False
        with tracing.span("deliver", sink="notes") as current:
            assert current is None


@pytest.mark.skipif(not OTEL_INSTALLED, reason="the [otel] extra is not installed")
class TestExtraPresent:
    def test_an_endpoint_plus_the_extra_enables_tracing(self):
        assert tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT}) is True
        assert tracing.enabled() is True

    def test_spans_carry_only_config_derived_and_structural_attributes(self):
        """No payload content, no headers, no rendered template output — see tracing.py.

        `redaction.py` exists because that material leaks; a span exporter is another egress.
        """
        tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT})
        with tracing.span(
            "ingest", source="github", event_type="issues.opened", verified=True
        ) as current:
            assert current is not None
            assert set(current.attributes) <= {"source", "event_type", "verified"}

    def test_a_none_attribute_is_dropped_rather_than_exported_as_a_string(self):
        tracing.configure(env={"OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT})
        with tracing.span("deliver", sink="notes", response_code=None) as current:
            assert "response_code" not in current.attributes

    def test_the_service_name_can_be_overridden(self):
        assert (
            tracing.configure(
                env={
                    "OTEL_EXPORTER_OTLP_ENDPOINT": ENDPOINT,
                    "OTEL_SERVICE_NAME": "doorman-forge",
                }
            )
            is True
        )
