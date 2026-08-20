"""Whole-stack tests: a real request, through verification, into the database, out to a sink.

The database test in `TestSecretsNeverReachDisk` is the one that justifies the design choice
behind `redaction.py`. It reads the SQLite file off disk as raw bytes and asserts the secret is
not in it — not that the redaction function was called, not that a column looks right. Testing
the mechanism would pass even if a later change persisted the header somewhere else.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from webhook_doorman.app import create_app
from webhook_doorman.config import Config
from webhook_doorman.engine import Engine
from webhook_doorman.secrets import resolve
from webhook_doorman.store import SqliteStore

from .conftest import GITHUB_SECRET, sign_hex

SINK_URL = "https://sink.example.invalid/notes"
ADMIN_TOKEN = "admin-token-for-tests-0123456789abcd"

BODY = json.dumps(
    {
        "action": "opened",
        "issue": {"number": 7, "title": "Something broke", "user": {"login": "octocat"}},
        "repository": {"full_name": "o/r"},
    }
).encode()


def config_data(**overrides) -> dict:
    return {
        "admin": {"token_env": "ADMIN_TOKEN"},
        # See test_engine.CONFIG: delivery is driven through `run_batch`, so the background
        # loop must not race it. A short tick here failed on CI and passed locally.
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


ENV = {"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET, "ADMIN_TOKEN": ADMIN_TOKEN}


@pytest.fixture
def stack(tmp_path):
    """A running app with a real engine over a real SQLite file."""
    db_path = tmp_path / "doorman.db"
    resolved = resolve(Config.model_validate(config_data()), ENV)
    engine = Engine(resolved, store=SqliteStore(db_path))
    app = create_app(resolved=resolved, engine=engine)
    with TestClient(app, client=("127.0.0.1", 51234)) as client:
        yield client, engine, db_path


def headers(body: bytes = BODY, delivery: str = "d-1") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, body, "sha256="),
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
    }


class TestEndToEnd:
    def test_a_signed_request_is_stored_and_delivered(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, _ = stack

        response = client.post("/webhook/github", content=BODY, headers=headers())
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

        assert run_batch(client, engine) == 1
        assert stats(client, engine)["deliveries_delivered"] == 1

    def test_delivery_reaches_the_sink(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, _ = stack
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)
        assert httpx_mock.get_requests()[0].read() == b'{"text": "[o/r#7] Something broke"}'

    def test_a_replayed_delivery_id_returns_200_and_does_not_double_post(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200, is_reusable=True)
        client, engine, _ = stack

        first = client.post("/webhook/github", content=BODY, headers=headers(BODY, "d-same"))
        run_batch(client, engine)
        second = client.post("/webhook/github", content=BODY, headers=headers(BODY, "d-same"))
        run_batch(client, engine)

        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["deduplicated"] is True
        assert len(httpx_mock.get_requests()) == 1

    def test_an_unsigned_request_never_reaches_storage(self, stack):
        client, engine, _ = stack
        assert client.post("/webhook/github", content=BODY).status_code == 401
        assert stats(client, engine)["events"] == 0


class TestSecretsNeverReachDisk:
    def test_the_webhook_secret_is_absent_from_the_database_file(self, stack, httpx_mock):
        """Read the file as raw bytes. Anything less tests the mechanism, not the property."""
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, db_path = stack

        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert GITHUB_SECRET.encode() not in read_all(db_path)

    def test_the_signature_header_is_absent_from_the_database_file(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, db_path = stack

        signature = headers()["X-Hub-Signature-256"]
        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert signature.encode() not in read_all(db_path)

    def test_a_secret_echoed_in_the_payload_is_absent_from_the_database_file(
        self, stack, httpx_mock
    ):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, db_path = stack

        body = json.dumps(
            {
                "action": "opened",
                "issue": {"number": 8, "title": "Leak", "body": GITHUB_SECRET, "user": {}},
                "repository": {"full_name": "o/r"},
            }
        ).encode()
        client.post("/webhook/github", content=body, headers=headers(body, "d-echo"))
        run_batch(client, engine)

        assert GITHUB_SECRET.encode() not in read_all(db_path)

    def test_the_admin_token_is_absent_from_the_database_file(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200)
        client, engine, db_path = stack

        client.post(
            "/webhook/github",
            content=BODY,
            headers={**headers(), "Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        run_batch(client, engine)

        assert ADMIN_TOKEN.encode() not in read_all(db_path)


class TestAdminReplay:
    def test_replay_requires_a_token(self, stack):
        client, _, _ = stack
        assert client.post("/admin/replay/1").status_code == 401

    def test_replay_rejects_a_wrong_token(self, stack):
        client, _, _ = stack
        response = client.post("/admin/replay/1", headers={"Authorization": "Bearer " + "x" * 36})
        assert response.status_code == 401

    def test_an_unauthenticated_caller_cannot_probe_which_events_exist(self, stack):
        """Both a real and a bogus id must answer 401, not 401 vs 404."""
        client, _, _ = stack
        assert client.post("/admin/replay/1").status_code == 401
        assert client.post("/admin/replay/999999").status_code == 401

    def test_replay_with_a_valid_token_requeues(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=200, is_reusable=True)
        client, engine, _ = stack

        posted = client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)
        assert len(httpx_mock.get_requests()) == 1

        event_id = posted.json()["event_id"]
        response = client.post(
            f"/admin/replay/{event_id}", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "replayed"

        run_batch(client, engine)
        assert len(httpx_mock.get_requests()) == 2

    def test_replaying_a_missing_event_is_404_when_authenticated(self, stack):
        client, _, _ = stack
        response = client.post(
            "/admin/replay/999999", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
        assert response.status_code == 404

    def test_a_source_path_may_not_be_mounted_under_admin(self):
        """The /admin/ deny rule at the proxy must not be able to shadow an ingest path."""
        data = config_data()
        data["sources"][0]["path"] = "/admin/webhook"
        with pytest.raises(ValueError, match="/admin"):
            Config.model_validate(data)


class TestHealthWithEngine:
    def test_reports_replay_enabled(self, stack):
        client, _, _ = stack
        assert client.get("/health").json()["replay_enabled"] is True

    def test_health_never_contains_a_secret(self, stack):
        client, _, _ = stack
        text = client.get("/health").text
        assert GITHUB_SECRET not in text
        assert ADMIN_TOKEN not in text


# -- helpers ---------------------------------------------------------------------------


def read_all(path: Path) -> bytes:
    """Every byte SQLite wrote, including the WAL sidecar.

    Checking only the main file would miss a secret sitting in an uncheckpointed WAL frame,
    which is where a just-written row actually lives.
    """
    data = b""
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            data += candidate.read_bytes()
    return data


def run_batch(client: TestClient, engine: Engine) -> int:
    """Drive one delivery batch on the app's event loop, synchronously.

    The engine's background loop is running, but waiting on it makes the suite slow when it
    passes and ambiguous when it fails.
    """
    return client.portal.call(engine.run_once)


def stats(client: TestClient, engine: Engine) -> dict[str, int]:
    return client.portal.call(engine.stats)
