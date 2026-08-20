"""End-to-end ingest behaviour through the ASGI app."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from webhook_doorman.app import create_app
from webhook_doorman.config import Config

from .conftest import BEARER_SECRET, GITHUB_SECRET, sign_hex

BODY = json.dumps(
    {
        "action": "opened",
        "issue": {
            "number": 7,
            "title": "Something broke",
            "html_url": "https://github.example.invalid/o/r/issues/7",
            "user": {"login": "octocat"},
            "body": "details",
        },
        "repository": {"full_name": "o/r"},
    }
).encode()


def build(
    config_data: dict,
    env: dict,
    captured: list | None = None,
    peer: str = "127.0.0.1",
):
    """Build a TestClient over the app.

    `peer` is passed through to Starlette's `client` scope value. It has to be set explicitly:
    TestClient's default is the literal string `"testclient"`, which is not an address, and a
    `none` source would reject it — correctly, but for the wrong reason to be testing.
    """

    async def ingest(event):
        if captured is not None:
            captured.append(event)
        return {"status": "accepted", "delivery_id": event.delivery_id}

    app = create_app(config=Config.model_validate(config_data), env=env, ingest=ingest)
    return TestClient(app, client=(peer, 51234))


def github_headers(body: bytes, delivery: str = "d-1") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, body, "sha256="),
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
    }


class TestIngest:
    def test_signed_request_accepted(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        resp = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))
        assert resp.status_code == 200
        assert len(captured) == 1
        assert captured[0].source == "github"
        assert captured[0].event_type == "issues.opened"
        assert captured[0].summary == "[o/r#7] Something broke"
        assert captured[0].sinks == ["notes"]

    def test_unsigned_request_rejected(self, base_config, base_env):
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=BODY, headers={"X-GitHub-Event": "issues"})
        assert resp.status_code == 401

    def test_mis_signed_request_rejected(self, base_config, base_env):
        client = build(base_config, base_env)
        headers = github_headers(BODY)
        headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64
        resp = client.post("/webhook/github", content=BODY, headers=headers)
        assert resp.status_code == 401

    def test_failure_response_does_not_leak_the_reason(self, base_config, base_env):
        """A caller learns 'no', not which check said no."""
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=BODY, headers={})
        assert resp.json()["detail"] == "Unauthorized"

    def test_source_with_unset_secret_is_disabled_and_rejects(self, base_config, base_env):
        """Never 'verification skipped' — the endpoint goes away instead."""
        del base_env["GITHUB_WEBHOOK_SECRET"]
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))
        assert resp.status_code == 503

    def test_blank_secret_counts_as_unset(self, base_config, base_env):
        base_env["GITHUB_WEBHOOK_SECRET"] = "   "
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))
        assert resp.status_code == 503

    def test_source_disabled_in_config_rejects(self, base_config, base_env):
        base_config["sources"][0]["enabled"] = False
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))
        assert resp.status_code == 503

    def test_bearer_source_accepted(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        resp = client.post(
            "/webhook/internal",
            content=b'{"event":"ping"}',
            headers={"Authorization": f"Bearer {BEARER_SECRET}"},
        )
        assert resp.status_code == 200
        assert captured[0].source == "internal"

    def test_bearer_source_rejects_wrong_token(self, base_config, base_env):
        client = build(base_config, base_env)
        resp = client.post(
            "/webhook/internal",
            content=b"{}",
            headers={"Authorization": "Bearer wrong-token-entirely"},
        )
        assert resp.status_code == 401

    def test_unknown_path_is_404(self, base_config, base_env):
        client = build(base_config, base_env)
        assert client.post("/webhook/nope", content=b"{}").status_code == 404


class TestBodyCap:
    def test_oversized_body_rejected(self, base_config, base_env):
        base_config["server"]["max_body_bytes"] = 64
        client = build(base_config, base_env)
        big = b"x" * 512
        resp = client.post("/webhook/github", content=big, headers=github_headers(big))
        assert resp.status_code == 413

    def test_oversized_body_rejected_before_verification(self, base_config, base_env):
        """413 must win over 401 — the cap exists so an attacker cannot make us buffer first."""
        base_config["server"]["max_body_bytes"] = 64
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=b"x" * 512, headers={})
        assert resp.status_code == 413

    def test_lying_content_length_still_capped(self, base_config, base_env):
        """A chunked body has no Content-Length to check; the stream cap is the real control."""
        base_config["server"]["max_body_bytes"] = 64

        def chunks():
            for _ in range(20):
                yield b"x" * 16

        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=chunks())
        assert resp.status_code == 413

    def test_body_at_the_limit_is_accepted(self, base_config, base_env):
        body = b'{"a":"' + b"x" * 50 + b'"}'
        base_config["server"]["max_body_bytes"] = len(body)
        client = build(base_config, base_env)
        resp = client.post("/webhook/github", content=body, headers=github_headers(body))
        assert resp.status_code == 200


class TestNoneSourcePeerCheck:
    @staticmethod
    def none_config(allow_from: list[str]) -> dict:
        return {
            "server": {"allow_unverified": True},
            "sources": [
                {
                    "name": "internal",
                    "path": "/webhook/internal",
                    "verify": {
                        "strategy": "none",
                        "unverified_reason": "host-side producer on loopback",
                        "allow_from": allow_from,
                    },
                    "sinks": ["notes"],
                }
            ],
            "sinks": [{"name": "notes", "type": "http", "url": "https://x.example.invalid"}],
        }

    def test_allowed_peer_accepted(self):
        client = build(self.none_config(["127.0.0.1/32"]), {}, peer="127.0.0.1")
        assert client.post("/webhook/internal", content=b"{}").status_code == 200

    def test_peer_inside_a_wider_cidr_accepted(self):
        client = build(self.none_config(["10.9.0.0/24"]), {}, peer="10.9.0.5")
        assert client.post("/webhook/internal", content=b"{}").status_code == 200

    def test_peer_outside_allowlist_rejected(self):
        client = build(self.none_config(["10.9.0.0/24"]), {}, peer="127.0.0.1")
        assert client.post("/webhook/internal", content=b"{}").status_code == 401

    def test_adjacent_peer_outside_the_cidr_rejected(self):
        client = build(self.none_config(["10.9.0.0/24"]), {}, peer="10.9.1.5")
        assert client.post("/webhook/internal", content=b"{}").status_code == 401

    def test_forwarded_for_cannot_forge_the_peer(self):
        """X-Forwarded-For is caller-controlled; it must not influence the allowlist.

        The connection comes from an address outside `allow_from` while every header a proxy
        would set claims an address inside it. Trusting any of them would flip this to 200.
        """
        client = build(self.none_config(["10.9.0.0/24"]), {}, peer="203.0.113.9")
        resp = client.post(
            "/webhook/internal",
            content=b"{}",
            headers={
                "X-Forwarded-For": "10.9.0.5",
                "X-Real-IP": "10.9.0.5",
                "Forwarded": "for=10.9.0.5",
            },
        )
        assert resp.status_code == 401

    def test_unverified_event_is_marked_unverified(self):
        captured: list = []
        client = build(self.none_config(["127.0.0.1/32"]), {}, captured)
        client.post("/webhook/internal", content=b"{}")
        assert captured[0].verified is False


class TestRedactionOnIngest:
    def test_signature_header_is_redacted_before_the_event_exists(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        client.post("/webhook/github", content=BODY, headers=github_headers(BODY))
        stored = captured[0].headers
        assert stored["x-hub-signature-256"] == "<redacted>"
        assert GITHUB_SECRET not in json.dumps(stored)

    def test_authorization_header_is_redacted(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        client.post(
            "/webhook/internal",
            content=b'{"event":"ping"}',
            headers={"Authorization": f"Bearer {BEARER_SECRET}"},
        )
        assert captured[0].headers["authorization"] == "<redacted>"
        assert BEARER_SECRET not in json.dumps(captured[0].headers)

    def test_secret_echoed_in_the_body_is_redacted(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        body = json.dumps({"echo": GITHUB_SECRET}).encode()
        client.post("/webhook/github", content=body, headers=github_headers(body))
        assert GITHUB_SECRET.encode() not in captured[0].body


class TestDeliveryId:
    def test_uses_the_configured_header(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        client.post("/webhook/github", content=BODY, headers=github_headers(BODY, "abc-123"))
        assert captured[0].delivery_id == "abc-123"

    def test_falls_back_to_a_body_digest(self, base_config, base_env):
        """A producer that sends no delivery header still gets dedup."""
        captured: list = []
        client = build(base_config, base_env, captured)
        headers = github_headers(BODY)
        del headers["X-GitHub-Delivery"]
        client.post("/webhook/github", content=BODY, headers=headers)
        assert captured[0].delivery_id.startswith("sha256:")

    def test_an_overlong_delivery_header_is_truncated_not_rejected(self, base_config, base_env):
        """The header is producer-controlled and lands in a unique index and every log line."""
        from webhook_doorman.app import MAX_DELIVERY_ID_LENGTH

        captured: list = []
        client = build(base_config, base_env, captured)
        resp = client.post(
            "/webhook/github", content=BODY, headers=github_headers(BODY, "x" * 5000)
        )
        assert resp.status_code == 200
        assert len(captured[0].delivery_id) == MAX_DELIVERY_ID_LENGTH

    def test_truncation_is_deterministic_so_dedup_still_works(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        for _ in range(2):
            client.post("/webhook/github", content=BODY, headers=github_headers(BODY, "y" * 5000))
        assert captured[0].delivery_id == captured[1].delivery_id

    def test_identical_bodies_produce_the_same_fallback_id(self, base_config, base_env):
        captured: list = []
        client = build(base_config, base_env, captured)
        for _ in range(2):
            client.post(
                "/webhook/internal",
                content=b'{"event":"ping"}',
                headers={"Authorization": f"Bearer {BEARER_SECRET}"},
            )
        assert captured[0].delivery_id == captured[1].delivery_id


class TestHealth:
    def test_reports_enabled_sources(self, base_config, base_env):
        client = build(base_config, base_env)
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["sources"]["github"]["enabled"] is True
        assert body["unverified_sources"] == []

    def test_reports_a_disabled_source_and_why(self, base_config, base_env):
        del base_env["GITHUB_WEBHOOK_SECRET"]
        client = build(base_config, base_env)
        entry = client.get("/health").json()["sources"]["github"]
        assert entry["enabled"] is False
        assert "GITHUB_WEBHOOK_SECRET" in entry["reason"]

    def test_names_unverified_sources(self):
        client = build(TestNoneSourcePeerCheck.none_config(["127.0.0.1/32"]), {})
        assert client.get("/health").json()["unverified_sources"] == ["internal"]

    def test_health_does_not_leak_secret_values(self, base_config, base_env):
        client = build(base_config, base_env)
        assert GITHUB_SECRET not in client.get("/health").text


class TestHealthStatusCode:
    """The status code is what `Dockerfile`'s HEALTHCHECK reads, so it carries the verdict.

    The distinction these tests pin down is partial vs. total. One disabled source out of two is
    a deliberate operator state on forge right now — a `GITHUB_WEBHOOK_SECRET` that has not been
    provisioned — and turning that into an unhealthy container would be a worse answer than the
    unconditional `ok` it replaces.
    """

    def test_partial_degradation_stays_healthy(self, base_config, base_env):
        del base_env["GITHUB_WEBHOOK_SECRET"]
        client = build(base_config, base_env)
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["sources"]["github"]["enabled"] is False
        assert body["sources"]["internal"]["enabled"] is True

    def test_zero_enabled_sources_is_degraded(self, base_config, base_env):
        client = build(base_config, {})
        response = client.get("/health")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "degraded"
        assert "no sources are enabled" in body["degraded"]

    def test_a_router_with_no_working_source_still_reports_why(self, base_config):
        """Degraded is not a substitute for the detail — the reasons stay in the body."""
        body = build(base_config, {}).get("/health").json()
        assert "GITHUB_WEBHOOK_SECRET" in body["sources"]["github"]["reason"]
        assert "INTERNAL_TOKEN" in body["sources"]["internal"]["reason"]


class StubEngine:
    """The minimum of `EngineLike` that `/health` and app construction touch."""

    def __init__(self, stats: dict | None = None, raises: Exception | None = None) -> None:
        self._stats = stats or {"events": 3, "deliveries": 5, "dlq": 1}
        self._raises = raises
        self.stats_calls = 0

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def ingest(self, event):  # pragma: no cover - not exercised by health tests
        return {"status": "accepted", "delivery_id": event.delivery_id}

    async def replay(self, event_id):  # pragma: no cover - not exercised by health tests
        return {"status": "replayed", "event_id": event_id}

    async def stats(self) -> dict:
        self.stats_calls += 1
        if self._raises is not None:
            raise self._raises
        return self._stats

    def check_admin_token(self, presented: str) -> bool:  # pragma: no cover - not exercised
        return False


def build_with_engine(config_data: dict, env: dict, engine) -> TestClient:
    app = create_app(config=Config.model_validate(config_data), env=env, engine=engine)
    return TestClient(app, client=("127.0.0.1", 51234))


class TestHealthStats:
    """`stats()` was implemented at three layers and called from nowhere but tests.

    `store/base.py` documents it as being "for `/health` and operator sanity", so the gap was in
    the wiring rather than the design.
    """

    def test_stats_are_included_when_an_engine_is_present(self, base_config, base_env):
        engine = StubEngine({"events": 3, "deliveries": 5, "dlq": 1, "deliveries_pending": 2})
        body = build_with_engine(base_config, base_env, engine).get("/health").json()
        assert body["stats"] == {
            "events": 3,
            "deliveries": 5,
            "dlq": 1,
            "deliveries_pending": 2,
        }
        assert engine.stats_calls == 1

    def test_no_engine_means_no_stats_key(self, base_config, base_env):
        """The log-only path has no store, so an absent key is the honest answer."""
        response = build(base_config, base_env).get("/health")
        assert response.status_code == 200
        assert "stats" not in response.json()

    def test_a_failing_stats_degrades_rather_than_500s(self, base_config, base_env):
        """An unreachable store reports the same as a dead process if this route 500s."""
        engine = StubEngine(raises=RuntimeError("store is not connected; call connect() first"))
        response = build_with_engine(base_config, base_env, engine).get("/health")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "degraded"
        assert "store is unavailable" in body["degraded"]
        assert "stats" not in body
        # The rest of the report survives a store failure — it is resolved config, not storage.
        assert body["sources"]["github"]["enabled"] is True

    def test_a_failing_stats_does_not_leak_the_exception_to_the_client(self, base_config, base_env):
        engine = StubEngine(raises=RuntimeError(f"connection string: {GITHUB_SECRET}"))
        text = build_with_engine(base_config, base_env, engine).get("/health").text
        assert GITHUB_SECRET not in text


class TestAppConstruction:
    def test_requires_a_config_source(self):
        with pytest.raises(ValueError, match="config or config_path"):
            create_app()

    def test_unknown_parser_fails_at_startup(self, base_config, base_env):
        """Not at first request — a broken parser must not wait for traffic to surface."""
        base_config["sources"][0]["parser"] = "nonexistent"
        with pytest.raises(Exception, match="unknown parser"):
            build(base_config, base_env)
