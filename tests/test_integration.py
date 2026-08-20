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
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/123456789/tok-0123456789abcdef"

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

    def test_a_secret_echoed_by_the_destination_is_absent_from_the_dlq(self, stack, httpx_mock):
        """The destination's *reply* is the route redaction did not cover.

        `redaction.py` runs at ingest, so it sees what the producer sent. `HttpSinkBase._send`
        puts part of the destination's response body into the error message, and `mark_exhausted`
        persisted that string verbatim — so a destination that echoes a submitted credential into
        its own 400 page wrote that credential into the DLQ, on the same disk, in the column an
        operator reads first. Asserted against raw bytes for the same reason as the cases above.
        """
        httpx_mock.add_response(
            url=SINK_URL,
            status_code=400,
            text=f"rejected token {GITHUB_SECRET} is not valid for this channel",
        )
        client, engine, db_path = stack

        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert stats(client, engine)["dlq"] == 1, "expected the 400 to dead-letter"
        assert GITHUB_SECRET.encode() not in read_all(db_path)

    def test_the_destination_error_still_reaches_the_dlq(self, stack, httpx_mock):
        """Redaction must not become deletion — the non-secret part is the diagnostic.

        A fix that dropped the destination's body entirely would pass the test above and leave
        an operator with `HTTP 400:` and nothing else.
        """
        httpx_mock.add_response(url=SINK_URL, status_code=400, text="channel_not_found")
        client, engine, db_path = stack

        client.post("/webhook/github", content=BODY, headers=headers())
        run_batch(client, engine)

        assert b"channel_not_found" in read_all(db_path)

    def test_a_discord_webhook_url_is_absent_from_the_database_file(self, tmp_path, httpx_mock):
        """The Discord/Slack credential is the *URL*, which is a shape redaction had not seen.

        Worth its own case rather than trusting the mechanism: until Plan 1 derived secret
        names from the model, a `webhook_url_env` field was invisible to `resolve()`, so the
        URL never entered `secret_values` and was never redacted. This asserts the property on
        disk — the same standard as the four cases above — for the field that exposed the gap.
        """
        httpx_mock.add_response(url=DISCORD_WEBHOOK_URL, status_code=204)

        data = config_data()
        data["sources"][0]["sinks"] = ["team-discord"]
        data["sinks"] = [
            {
                "name": "team-discord",
                "type": "discord",
                "webhook_url_env": "DISCORD_WEBHOOK_URL",
                # Echo the credential into the message body, which is the way it would
                # realistically reach the store: rendered content is persisted with the event.
                "template": "{{ summary }} DISCORD_WEBHOOK_URL",
            }
        ]

        db_path = tmp_path / "doorman.db"
        env = {**ENV, "DISCORD_WEBHOOK_URL": DISCORD_WEBHOOK_URL}
        resolved = resolve(Config.model_validate(data), env)
        engine = Engine(resolved, store=SqliteStore(db_path))
        app = create_app(resolved=resolved, engine=engine)

        with TestClient(app, client=("127.0.0.1", 51234)) as client:
            body = json.dumps(
                {
                    "action": "opened",
                    "issue": {
                        "number": 9,
                        "title": "Leak",
                        "body": DISCORD_WEBHOOK_URL,
                        "user": {},
                    },
                    "repository": {"full_name": "o/r"},
                }
            ).encode()
            client.post("/webhook/github", content=body, headers=headers(body, "d-discord"))
            run_batch(client, engine)

        assert DISCORD_WEBHOOK_URL.encode() not in read_all(db_path)


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


AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def dead_letter(client: TestClient, engine: Engine, n: int) -> None:
    """Drive `n` events all the way to the DLQ. `max_attempts` is 2, so one 400 is terminal."""
    for i in range(n):
        client.post("/webhook/github", content=BODY, headers=headers(BODY, f"dlq-{i}"))
        run_batch(client, engine)


class TestAdminDlq:
    def test_requires_a_token(self, stack):
        client, _, _ = stack
        assert client.get("/admin/dlq").status_code == 401

    def test_rejects_a_wrong_token(self, stack):
        client, _, _ = stack
        assert (
            client.get("/admin/dlq", headers={"Authorization": "Bearer " + "x" * 36}).status_code
            == 401
        )

    def test_a_short_token_is_rejected(self, stack):
        """`check_admin_token` compares against the configured value, which has a length floor."""
        client, _, _ = stack
        assert client.get("/admin/dlq", headers={"Authorization": "Bearer abc"}).status_code == 401

    def test_the_token_is_checked_before_the_queue_is_read(self, stack, httpx_mock):
        """A populated DLQ and an empty one must be indistinguishable without a token.

        Asserting on the *body* rather than only the status: a handler that queried first and
        rejected second would still answer 401, but would have done the read — and any detail
        that leaked into the error body would leak the queue's shape with it.
        """
        httpx_mock.add_response(url=SINK_URL, status_code=400, is_reusable=True)
        client, engine, _ = stack
        dead_letter(client, engine, 3)

        response = client.get("/admin/dlq")
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

    def test_lists_the_failure_metadata_needed_to_replay(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=400, text="channel_not_found")
        client, engine, _ = stack
        dead_letter(client, engine, 1)

        body = client.get("/admin/dlq", headers=AUTH).json()
        assert body["count"] == 1
        entry = body["entries"][0]
        assert entry["source"] == "github"
        assert entry["sink"] == "notes"
        assert entry["response_code"] is None or isinstance(entry["response_code"], int)
        assert "channel_not_found" in entry["error"]
        # The point of the endpoint: this is the id `POST /admin/replay/{id}` takes.
        assert client.post(f"/admin/replay/{entry['event_id']}", headers=AUTH).status_code == 200

    def test_the_response_carries_no_payload(self, stack, httpx_mock):
        """Failure metadata, not stored request bodies. The event body is replay-only."""
        httpx_mock.add_response(url=SINK_URL, status_code=400)
        client, engine, _ = stack
        dead_letter(client, engine, 1)

        response = client.get("/admin/dlq", headers=AUTH)
        entry = response.json()["entries"][0]
        assert not {"payload", "body", "context", "headers"} & set(entry)
        # Asserted on the raw text too — a nested field would satisfy the key check above.
        assert "octocat" not in response.text
        assert "Something broke" not in response.text

    def test_limit_is_clamped_server_side(self, stack, httpx_mock):
        """A cap the caller can raise is not a cap."""
        httpx_mock.add_response(url=SINK_URL, status_code=400, is_reusable=True)
        client, engine, _ = stack
        dead_letter(client, engine, 3)

        body = client.get("/admin/dlq?limit=100000", headers=AUTH).json()
        assert body["limit"] == 100
        assert body["count"] == 3

    def test_keyset_paging_returns_each_row_exactly_once(self, stack, httpx_mock):
        httpx_mock.add_response(url=SINK_URL, status_code=400, is_reusable=True)
        client, engine, _ = stack
        dead_letter(client, engine, 5)

        first = client.get("/admin/dlq?limit=2", headers=AUTH).json()
        assert first["count"] == 2
        second = client.get(
            f"/admin/dlq?limit=2&before_id={first['next_before_id']}", headers=AUTH
        ).json()

        ids = [e["id"] for e in first["entries"] + second["entries"]]
        assert ids == sorted(ids, reverse=True), "newest first, across the page boundary"
        assert len(set(ids)) == 4, "no row returned twice"

    def test_a_short_page_offers_no_cursor(self, stack, httpx_mock):
        """Otherwise a client loops forever on an exhausted queue."""
        httpx_mock.add_response(url=SINK_URL, status_code=400, is_reusable=True)
        client, engine, _ = stack
        dead_letter(client, engine, 2)

        assert client.get("/admin/dlq?limit=50", headers=AUTH).json()["next_before_id"] is None

    def test_an_empty_queue_is_200_not_404(self, stack):
        client, _, _ = stack
        body = client.get("/admin/dlq", headers=AUTH).json()
        assert body == {"count": 0, "limit": 50, "next_before_id": None, "entries": []}


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
