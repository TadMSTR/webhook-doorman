"""Ingest-path hardening from the 0.7.0 review.

Each class pins one behaviour the review found missing: a test here fails if that protection
is removed. Secrets and hosts are synthetic.
"""

from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

from webhook_doorman.app import create_app
from webhook_doorman.config import Config
from webhook_doorman.parsers import parse
from webhook_doorman.redaction import REDACTED, redact_bytes
from webhook_doorman.secrets import resolve

from .conftest import GITHUB_SECRET, sign_hex

#: Shaped like a Discord webhook URL, the case where the URL is the credential.
SINK_URL_SECRET = "https://discord.example.invalid/api/webhooks/1/t0k3n-NOTREAL-abäcd"


def config_data(**overrides) -> dict:
    return {
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
                "sinks": ["chat"],
            },
            {
                "name": "custom",
                "path": "/webhook/custom",
                "verify": {
                    "strategy": "bearer",
                    "header": "X-Custom-Token",
                    "prefix": "",
                    "secret_env": "SHORT_TOKEN",
                },
                "sinks": ["chat"],
            },
        ],
        "sinks": [{"name": "chat", "type": "discord", "webhook_url_env": "DISCORD_URL"}],
        **overrides,
    }


ENV = {
    "GITHUB_WEBHOOK_SECRET": GITHUB_SECRET,
    "SHORT_TOKEN": "abc12",  # under MIN_REDACTABLE_LENGTH: only the name pass can hide it
    "DISCORD_URL": SINK_URL_SECRET,
}


def build(captured: list, data: dict | None = None, env: dict | None = None) -> TestClient:
    async def ingest(event):
        captured.append(event)
        return {"status": "accepted"}

    app = create_app(
        config=Config.model_validate(data or config_data()), env=env or ENV, ingest=ingest
    )
    return TestClient(app, client=("127.0.0.1", 51234))


def post_github(client: TestClient, body: bytes, event: str = "issues"):
    return client.post(
        "/webhook/github",
        content=body,
        headers={
            "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, body, "sha256="),
            "X-GitHub-Event": event,
            "Content-Type": "application/json",
        },
    )


class TestEscapedSecretsAreRedacted:
    """A secret JSON-escaped in the body is redacted in the stored body AND in `payload`."""

    @pytest.mark.parametrize("ensure_ascii", [True, False])
    @pytest.mark.parametrize("escape_slash", [True, False])
    def test_redact_bytes_covers_encoder_spellings(self, ensure_ascii, escape_slash):
        text = json.dumps({"echo": SINK_URL_SECRET}, ensure_ascii=ensure_ascii)
        if escape_slash:
            text = text.replace("/", "\\/")
        out = redact_bytes(text.encode("utf-8"), [SINK_URL_SECRET])
        assert REDACTED.encode() in out
        assert json.loads(out)["echo"] == REDACTED

    def test_an_arbitrary_escape_is_caught_in_the_decoded_payload(self):
        """No byte pass can know every escape a producer might use; the decoded pass does."""
        # `t` written as a \\u0074 escape, which no standard JSON encoder emits.
        body = json.dumps(
            {
                "action": "opened",
                "issue": {"number": 1, "title": "t", "user": {"login": "u"}, "body": "x"},
                "repository": {"full_name": "o/r"},
                "echo": SINK_URL_SECRET,
            }
        ).encode()
        body = body.replace(b"t0k3n", b"\\u00740k3n")
        captured: list = []
        with build(captured) as client:
            assert post_github(client, body).status_code == 200
        assert SINK_URL_SECRET not in json.dumps(captured[0].payload)
        assert captured[0].payload["echo"] == REDACTED


class TestCustomCredentialHeaderIsRedactedByName:
    """A source's own credential header is redacted by name, whatever its value's length."""

    def test_a_short_token_in_a_custom_header_is_not_stored(self):
        captured: list = []
        with build(captured) as client:
            response = client.post(
                "/webhook/custom", content=b"{}", headers={"X-Custom-Token": "abc12"}
            )
            assert response.status_code == 200
        assert captured[0].headers["x-custom-token"] != "abc12"


class TestBodiesPythonCannotDecodeAreStoredNotFailed:
    """JSON this process cannot hold is a non-JSON event, never a 500."""

    @pytest.mark.parametrize(
        "body",
        [
            b'{"a": ' + b"9" * 5000 + b"}",  # over the int-conversion limit: ValueError
            b"[" * 200_000 + b"]" * 200_000,  # deep nesting: RecursionError
        ],
        ids=["huge-int", "deep-nesting"],
    )
    def test_it_is_accepted_as_unparseable(self, body):
        data = config_data(server={"max_body_bytes": 1_000_000})
        captured: list = []
        with build(captured, data) as client:
            response = post_github(client, body)
        assert response.status_code == 200
        assert captured[0].payload is None
        assert captured[0].sinks == []


class TestAParserThatRaisesIsAnUnparseableEvent:
    @pytest.mark.parametrize(
        ("parser", "payload"),
        [
            ("grafana", {"status": 5, "alerts": []}),
            ("github", {"action": "opened", "issue": {"body": 5, "title": "t"}}),
        ],
    )
    def test_it_does_not_raise(self, parser, payload):
        result = parse(parser, json.dumps(payload).encode(), {"x-github-event": "issues"})
        assert result.actionable is False

    def test_over_http_it_is_a_200_not_a_500(self):
        body = json.dumps({"action": "opened", "issue": {"body": 5, "title": "t"}}).encode()
        captured: list = []
        with build(captured) as client:
            assert post_github(client, body).status_code == 200
        assert captured[0].sinks == []


class TestNonActionableEventsAreNotDispatched:
    """At the app level: a non-actionable event is stored with no sinks and not `filtered`."""

    def test_a_closed_issue_goes_nowhere_and_is_not_filtered(self):
        body = json.dumps(
            {
                "action": "closed",
                "issue": {"number": 1, "title": "t", "user": {"login": "u"}, "body": "x"},
                "repository": {"full_name": "o/r"},
            }
        ).encode()
        captured: list = []
        with build(captured) as client:
            assert post_github(client, body).status_code == 200
        event = captured[0]
        assert event.sinks == []
        assert event.status.value == "received"
        assert event.filter_reason is None


class TestConfigRefusesAmbiguousRouting:
    def test_a_sink_listed_twice_in_one_source_is_rejected(self):
        data = config_data()
        data["sources"][0]["sinks"] = ["chat", "chat"]
        with pytest.raises(ValueError, match="listed more than once"):
            Config.model_validate(data)

    @pytest.mark.parametrize("path", ["/{rest:path}", "/hooks/{name}", "/x}"])
    def test_a_templated_path_is_rejected(self, path):
        data = copy.deepcopy(config_data())
        data["sources"][0]["path"] = path
        with pytest.raises(ValueError, match="must be literal"):
            Config.model_validate(data)


class TestBlankTokensAreAbsent:
    """A blank token never enables anything, even with `min_token_length: 0`."""

    @pytest.mark.parametrize("value", ["", "   "])
    def test_admin_and_metrics(self, value):
        data = config_data(
            admin={"token_env": "ADMIN_TOKEN", "min_token_length": 0},
            metrics={"token_env": "METRICS_TOKEN", "min_token_length": 0},
        )
        resolved = resolve(
            Config.model_validate(data), {**ENV, "ADMIN_TOKEN": value, "METRICS_TOKEN": value}
        )
        assert resolved.admin_token() is None
        assert resolved.metrics_token() is None


class TestNoSchemaOrDocsEndpoints:
    @pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
    def test_they_are_not_served(self, path):
        with build([]) as client:
            assert client.get(path).status_code == 404
