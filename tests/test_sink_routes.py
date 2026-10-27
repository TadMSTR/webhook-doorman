"""Per-sink filters: one source, different subsets of its events to different sinks.

The motivating case is a Vikunja source feeding two sinks: a chat room that wants tasks created
and completed, and a push channel that wants only new high or urgent tasks. Before routes, that
took a second Vikunja webhook with its own secret. Now it is config.

The fixture below has the key structure of a real Vikunja `task.created` delivery (read from a
stored delivery's shape, keys and types only). Every value is invented.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from webhook_doorman.app import create_app
from webhook_doorman.config import Config, SinkRoute, load_config
from webhook_doorman.engine import Engine
from webhook_doorman.errors import ConfigError
from webhook_doorman.filtering import route
from webhook_doorman.metrics import METRICS
from webhook_doorman.secrets import resolve
from webhook_doorman.store import SqliteStore

from .conftest import sign_hex

VIKUNJA_SECRET = "test-vikunja-secret-0123456789abcdef"
ADMIN = "test-admin-token-0123456789abcdefghij"
REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_CONFIGS = [
    REPO_ROOT / "config.example.yml",
    *sorted((REPO_ROOT / "examples").glob("*.yml")),
]


def vikunja_payload(
    event_name: str = "task.created", *, priority: int = 0, done: bool = False, task_id: int = 41
) -> dict:
    """A Vikunja webhook body in the shape Vikunja actually sends. Values are synthetic."""
    user = {
        "id": 1,
        "name": "",
        "username": "demo",
        "created": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
    }
    return {
        "event_name": event_name,
        "time": "2026-10-27T09:00:00Z",
        "data": {
            "doer": user,
            "project": {
                "id": 7,
                "title": "Demo",
                "description": "",
                "identifier": "",
                "hex_color": "",
                "is_archived": False,
                "is_favorite": False,
                "max_permission": 2,
                "owner": user,
                "parent_project_id": 0,
                "position": 0,
                "background_blur_hash": "",
                "background_information": None,
                "views": [],
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
            },
            "task": {
                "id": task_id,
                "title": "Rotate the backup key",
                "description": "",
                "done": done,
                "done_at": "0001-01-01T00:00:00Z",
                "due_date": "0001-01-01T00:00:00Z",
                "start_date": "0001-01-01T00:00:00Z",
                "end_date": "0001-01-01T00:00:00Z",
                "priority": priority,
                "percent_done": 0,
                "project_id": 7,
                "identifier": "#41",
                "index": 41,
                "hex_color": "",
                "is_favorite": False,
                "bucket_id": 0,
                "buckets": [],
                "position": 0,
                "repeat_after": 0,
                "repeat_mode": 0,
                "cover_image_attachment_id": 0,
                "created_by": user,
                "assignees": None,
                "attachments": None,
                "labels": None,
                "reactions": None,
                "reminders": None,
                "related_tasks": {},
                "created": "2026-10-27T09:00:00Z",
                "updated": "2026-10-27T09:00:00Z",
            },
        },
    }


#: The matrix-notify-overhaul p1 shape: chat gets created + done, push gets created at 3-4.
CONFIG: dict = {
    "admin": {"token_env": "ADMIN_TOKEN"},
    "delivery": {"poll_interval_seconds": 3600},
    "sources": [
        {
            "name": "vikunja",
            "path": "/webhook/vikunja",
            "parser": "vikunja",
            "verify": {
                "strategy": "hmac_sha256",
                "header": "X-Vikunja-Signature",
                "secret_env": "VIKUNJA_WEBHOOK_SECRET",
            },
            "sinks": [
                {"name": "chat", "filter": {"event_types": ["task.created", "task.done"]}},
                {
                    "name": "push",
                    "filter": {
                        "event_types": ["task.created"],
                        "require": {"data.task.priority": ["3", "4"]},
                    },
                },
            ],
        }
    ],
    "sinks": [
        {"name": "chat", "type": "http", "url": "https://chat.example.invalid/hook"},
        {"name": "push", "type": "http", "url": "https://push.example.invalid/hook"},
    ],
}
ENV = {"VIKUNJA_WEBHOOK_SECRET": VIKUNJA_SECRET, "ADMIN_TOKEN": ADMIN}


@pytest.fixture(autouse=True)
def clean_metrics():
    METRICS.reset()
    yield
    METRICS.reset()


@pytest.fixture
def stack(tmp_path):
    resolved = resolve(Config.model_validate(CONFIG), ENV)
    engine = Engine(resolved, store=SqliteStore(tmp_path / "routes.db"))
    app = create_app(resolved=resolved, engine=engine)
    with TestClient(app, client=("127.0.0.1", 51234)) as client:
        yield client, engine


def post(client: TestClient, payload: dict, delivery: str) -> dict:
    body = json.dumps(payload).encode()
    response = client.post(
        "/webhook/vikunja",
        content=body,
        headers={
            "X-Vikunja-Signature": sign_hex(VIKUNJA_SECRET, body),
            "Content-Type": "application/json",
            # Vikunja sends no delivery id; dedup falls back to the body hash, so each test
            # event differs in task_id to stay distinct.
            "X-Test-Delivery": delivery,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


async def sinks_of(engine: Engine, event_id: int) -> list[str]:
    cursor = await engine.store.db.execute(
        "SELECT sink FROM deliveries WHERE event_id = ? ORDER BY sink", (event_id,)
    )
    return [row["sink"] for row in await cursor.fetchall()]


def counter(client: TestClient, sink: str, reason: str) -> float:
    for line in client.get("/metrics").text.splitlines():
        if line.startswith("webhook_doorman_deliveries_filtered_total{") and (
            f'sink="{sink}"' in line and f'reason="{reason}"' in line
        ):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"no deliveries_filtered_total series for sink={sink} reason={reason}")


# -- config ---------------------------------------------------------------------------------


class TestConfig:
    def test_a_bare_name_is_an_unfiltered_route(self):
        data = copy.deepcopy(CONFIG)
        data["sources"][0]["sinks"] = ["chat", "push"]
        config = Config.model_validate(data)
        assert config.sources[0].sinks == [SinkRoute(name="chat"), SinkRoute(name="push")]
        assert config.sources[0].sink_names == ["chat", "push"]

    def test_names_and_routes_mix(self):
        data = copy.deepcopy(CONFIG)
        data["sources"][0]["sinks"] = ["chat", {"name": "push", "filter": {"event_types": ["x"]}}]
        source = Config.model_validate(data).sources[0]
        assert source.sinks[0].filter is None
        assert source.sinks[1].filter.event_types == ["x"]

    def test_a_route_to_an_unknown_sink_is_a_startup_error(self, tmp_path):
        data = copy.deepcopy(CONFIG)
        data["sources"][0]["sinks"][1]["name"] = "pager"
        path = tmp_path / "c.yml"
        path.write_text(yaml.safe_dump(data))
        with pytest.raises(ConfigError, match="unknown sink 'pager'"):
            load_config(path)

    @pytest.mark.parametrize(
        "bad",
        [
            {"event_types": []},
            {"require": {"data.task.priority": []}},
            {"max_field_bytes": 10},  # per-source only: the stored event is shared
            {"unknown_gate": ["x"]},
        ],
    )
    def test_a_bad_route_filter_is_rejected(self, bad):
        data = copy.deepcopy(CONFIG)
        data["sources"][0]["sinks"][0]["filter"] = bad
        with pytest.raises(ValueError):
            Config.model_validate(data)


class TestShippedConfigsAreUnchanged:
    """Every config written before routes existed means what it meant (plan item 5.2)."""

    @pytest.mark.parametrize("path", SHIPPED_CONFIGS, ids=lambda p: p.name)
    def test_bare_names_load_as_unfiltered_routes_in_order(self, path):
        raw = yaml.safe_load(path.read_text())
        config = load_config(path)
        for raw_source, source in zip(raw["sources"], config.sources, strict=True):
            names = [s if isinstance(s, str) else s["name"] for s in raw_source["sinks"]]
            assert source.sink_names == names
            for raw_entry, entry in zip(raw_source["sinks"], source.sinks, strict=True):
                if isinstance(raw_entry, str):
                    assert entry.filter is None


# -- matching -------------------------------------------------------------------------------


class TestTypedMatching:
    """Values are compared as text. Pinned, because the matrix p1 use case depends on it."""

    PUSH = Config.model_validate(CONFIG).sources[0].sinks

    @pytest.mark.parametrize(
        ("priority", "expected"), [(0, False), (2, False), (3, True), (4, True), (5, False)]
    )
    def test_an_integer_priority_matches_its_string_form(self, priority, expected):
        sinks, refused = route(self.PUSH, "task.created", vikunja_payload(priority=priority))
        assert ("push" in sinks) is expected
        if not expected:
            assert refused["push"].reason == "require"
            assert refused["push"].detail == "data.task.priority"

    def test_a_route_without_a_filter_takes_everything(self):
        routes = [SinkRoute(name="all")]
        assert route(routes, "anything", None) == (["all"], {})


# -- end to end -----------------------------------------------------------------------------


class TestVikunjaToChatAndPush:
    async def test_a_new_urgent_task_reaches_both(self, stack):
        client, engine = stack
        body = post(client, vikunja_payload(priority=4, task_id=1), "a")
        assert body["status"] == "accepted"
        assert await sinks_of(engine, body["event_id"]) == ["chat", "push"]

    async def test_a_new_low_task_reaches_chat_only(self, stack):
        client, engine = stack
        body = post(client, vikunja_payload(priority=1, task_id=2), "b")
        assert await sinks_of(engine, body["event_id"]) == ["chat"]
        assert counter(client, "push", "require") == 1

    async def test_a_completed_task_reaches_chat_only(self, stack):
        client, engine = stack
        done = vikunja_payload("task.updated", priority=4, done=True, task_id=3)
        body = post(client, done, "c")
        assert await sinks_of(engine, body["event_id"]) == ["chat"]
        assert counter(client, "push", "event_type") == 1

    async def test_an_event_every_route_refuses_is_stored_as_filtered(self, stack, capsys):
        client, engine = stack
        body = post(client, vikunja_payload("task.updated", priority=4, task_id=4), "d")
        assert body == {
            "status": "filtered",
            "event_id": body["event_id"],
            "reason": "sink",
            "sinks": ["chat", "push"],
        }
        assert await sinks_of(engine, body["event_id"]) == []
        stored = await engine.store.get_event(body["event_id"])
        assert stored.status.value == "filtered"
        out = capsys.readouterr().out
        assert "event_filtered" in out
        assert out.count("delivery_filtered") == 2

    async def test_a_redelivery_does_not_count_twice(self, stack):
        client, _ = stack
        payload = vikunja_payload(priority=1, task_id=5)
        post(client, payload, "e")
        assert post(client, payload, "e")["deduplicated"] is True
        assert counter(client, "push", "require") == 1

    async def test_replay_reapplies_the_routes(self, stack):
        client, engine = stack
        body = post(client, vikunja_payload(priority=1, task_id=6), "f")
        replayed = client.post(
            f"/admin/replay/{body['event_id']}", headers={"Authorization": f"Bearer {ADMIN}"}
        ).json()
        assert replayed["sinks"] == ["chat"]
        assert await sinks_of(engine, body["event_id"]) == ["chat", "chat"]

    def test_series_exist_at_zero_for_filtered_routes_only(self, stack):
        client, _ = stack
        text = client.get("/metrics").text
        for reason in ("event_type", "require", "deny"):
            assert counter(client, "push", reason) == 0
            assert counter(client, "chat", reason) == 0
        assert 'sink="nonexistent"' not in text


class TestTheShippedVikunjaExample:
    """`examples/vikunja-chat-and-push.yml` routes the way its comments say it does."""

    ROUTES = load_config(REPO_ROOT / "examples" / "vikunja-chat-and-push.yml").sources[0].sinks

    @pytest.mark.parametrize(
        ("event_type", "priority", "expected"),
        [
            ("task.created", 4, ["task-room", "phone"]),
            ("task.created", 3, ["task-room", "phone"]),
            ("task.created", 2, ["task-room"]),
            ("task.created", 0, ["task-room"]),
            ("task.done", 4, ["task-room"]),
            ("task.updated", 4, []),
            ("task.comment.created", 4, []),
        ],
    )
    def test_routing(self, event_type, priority, expected):
        sinks, _ = route(self.ROUTES, event_type, vikunja_payload(priority=priority))
        assert sinks == expected
