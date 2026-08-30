"""Structural admission control: event allowlists, payload requirements, field caps.

The unit tests here drive `filtering` directly; the last two classes drive a real request
through the app and into the store, because the claim worth defending is not "the predicate
returns False" but "the event was stored and nothing was queued for it".
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from webhook_doorman.app import create_app
from webhook_doorman.config import Config, SourceFilter
from webhook_doorman.errors import ConfigError
from webhook_doorman.filtering import (
    FILTER_REASONS,
    TRUNCATION_MARKER,
    dig,
    evaluate,
    truncate,
    truncate_text,
)
from webhook_doorman.metrics import METRICS
from webhook_doorman.models import EventStatus

from .conftest import GITHUB_SECRET, sign_hex

PAYLOAD = {
    "action": "opened",
    "issue": {
        "number": 7,
        "title": "Something broke",
        "author_association": "OWNER",
        "draft": False,
        "labels": ["bug", "triage"],
        "user": {"login": "octocat"},
        "body": "details",
    },
    "repository": {"full_name": "o/r"},
}


def make_filter(**kwargs) -> SourceFilter:
    return SourceFilter.model_validate(kwargs)


class TestEventTypeAllowlist:
    def test_admits_a_listed_type(self):
        verdict = evaluate(make_filter(event_types=["issues.opened"]), "issues.opened", PAYLOAD)
        assert verdict.admitted is True
        assert verdict.reason is None

    def test_rejects_an_unlisted_type(self):
        verdict = evaluate(make_filter(event_types=["push"]), "issues.opened", PAYLOAD)
        assert verdict.admitted is False
        assert verdict.reason == "event_type"

    def test_an_unset_allowlist_admits_everything(self):
        assert evaluate(make_filter(), "anything.at.all", PAYLOAD).admitted is True


class TestRequire:
    def test_a_present_matching_path_is_admitted(self):
        f = make_filter(require={"issue.author_association": ["OWNER", "MEMBER"]})
        assert evaluate(f, "issues.opened", PAYLOAD).admitted is True

    def test_a_present_mismatched_path_is_refused(self):
        f = make_filter(require={"issue.author_association": ["MEMBER"]})
        verdict = evaluate(f, "issues.opened", PAYLOAD)
        assert verdict.admitted is False
        assert verdict.reason == "require"

    def test_an_absent_path_fails_the_requirement(self):
        """Fail-closed: the payload did not carry the guarantee that was asked for."""
        f = make_filter(require={"issue.no_such_field": ["anything"]})
        verdict = evaluate(f, "issues.opened", PAYLOAD)
        assert verdict.admitted is False
        assert verdict.reason == "require"

    def test_a_path_through_a_non_dict_does_not_raise(self):
        f = make_filter(require={"issue.number.nested.deeper": ["1"]})
        assert evaluate(f, "issues.opened", PAYLOAD).admitted is False

    def test_a_non_dict_payload_does_not_raise(self):
        f = make_filter(require={"anything": ["1"]})
        assert evaluate(f, "webhook", None).admitted is False
        assert evaluate(f, "webhook", ["a", "list"]).admitted is False

    def test_detail_names_the_path_and_never_the_value(self):
        f = make_filter(require={"issue.author_association": ["MEMBER"]})
        verdict = evaluate(f, "issues.opened", PAYLOAD)
        assert verdict.detail == "issue.author_association"
        assert "OWNER" not in (verdict.detail or "")


class TestDeny:
    def test_a_matching_value_is_refused(self):
        f = make_filter(deny={"issue.author_association": ["NONE", "FIRST_TIME_CONTRIBUTOR"]})
        payload = json.loads(json.dumps(PAYLOAD))
        payload["issue"]["author_association"] = "NONE"
        verdict = evaluate(f, "issues.opened", payload)
        assert verdict.admitted is False
        assert verdict.reason == "deny"

    def test_a_non_matching_value_is_admitted(self):
        f = make_filter(deny={"issue.author_association": ["NONE"]})
        assert evaluate(f, "issues.opened", PAYLOAD).admitted is True

    def test_an_absent_path_passes(self):
        """Asymmetric with `require` on purpose: absent is not the thing being refused."""
        f = make_filter(deny={"issue.no_such_field": ["anything"]})
        assert evaluate(f, "issues.opened", PAYLOAD).admitted is True

    def test_a_payload_failing_both_gates_is_reported_as_deny(self):
        """The case that actually pins the evaluation order.

        When only `deny` would reject, any order gives the same answer — so a test built that way
        passes whichever gate runs first. This is the one that distinguishes them: `require`
        fails *and* `deny` matches, so the reported reason says which gate was consulted first.
        """
        f = make_filter(
            require={"issue.author_association": ["MEMBER"]},  # payload says OWNER: fails
            deny={"repository.full_name": ["o/r"]},  # also matches
        )
        verdict = evaluate(f, "issues.opened", PAYLOAD)
        assert verdict.admitted is False
        assert verdict.reason == "deny"
        assert verdict.detail == "repository.full_name"

    def test_deny_takes_precedence_over_require(self):
        """A payload satisfying `require` and matching `deny` is refused, and refused as deny."""
        f = make_filter(
            require={"issue.author_association": ["OWNER"]},
            deny={"repository.full_name": ["o/r"]},
        )
        verdict = evaluate(f, "issues.opened", PAYLOAD)
        assert verdict.admitted is False
        assert verdict.reason == "deny"


class TestValueMatching:
    def test_a_json_boolean_matches_its_json_spelling(self):
        """`str(False)` is `"False"`; the payload and the YAML both say `false`."""
        assert evaluate(make_filter(deny={"issue.draft": ["false"]}), "e", PAYLOAD).reason == "deny"
        assert evaluate(make_filter(deny={"issue.draft": ["False"]}), "e", PAYLOAD).admitted is True

    def test_a_true_matches_its_json_spelling(self):
        payload = {"pull_request": {"draft": True}}
        f = make_filter(require={"pull_request.draft": ["true"]})
        assert evaluate(f, "e", payload).admitted is True

    def test_a_null_inside_a_list_matches_as_null(self):
        """`dig` short-circuits a top-level null, so this is the only path that reaches it."""
        payload = {"issue": {"assignees": [None]}}
        f = make_filter(deny={"issue.assignees": ["null"]})
        assert evaluate(f, "e", payload).reason == "deny"

    def test_a_number_matches_as_text(self):
        assert evaluate(make_filter(require={"issue.number": ["7"]}), "e", PAYLOAD).admitted is True

    def test_a_list_matches_if_any_element_does(self):
        f = make_filter(deny={"issue.labels": ["triage"]})
        assert evaluate(f, "e", PAYLOAD).reason == "deny"

    def test_a_list_with_no_matching_element_does_not_match(self):
        f = make_filter(deny={"issue.labels": ["wontfix"]})
        assert evaluate(f, "e", PAYLOAD).admitted is True


class TestDig:
    def test_resolves_a_nested_path(self):
        assert dig(PAYLOAD, "issue.user.login") == "octocat"

    def test_returns_none_for_a_missing_path(self):
        assert dig(PAYLOAD, "issue.absent") is None

    def test_returns_none_rather_than_raising_on_a_scalar(self):
        assert dig(PAYLOAD, "issue.number.deeper") is None


class TestTruncation:
    def test_a_short_string_is_untouched(self):
        assert truncate_text("hello", 32) == "hello"

    def test_an_exact_fit_is_untouched(self):
        assert truncate_text("abcd", 4) == "abcd"

    def test_an_over_long_string_is_marked(self):
        out = truncate_text("abcdefghij", 4)
        assert out == "abcd" + TRUNCATION_MARKER

    def test_the_cut_lands_on_a_character_boundary(self):
        """A byte-index slice of UTF-8 produces a string that is no longer valid UTF-8.

        `é` is two bytes, so a four-byte budget over `ééé` must yield two characters and not a
        lone continuation byte. The assertion is that the result round-trips, which is the
        property that matters — an invalid-UTF-8 field breaks JSON encoding at the sink.
        """
        out = truncate_text("ééé", 5)
        assert out == "éé" + TRUNCATION_MARKER
        out.encode("utf-8").decode("utf-8")

    def test_the_budget_is_bytes_not_characters(self):
        assert truncate_text("ééé", 6) == "ééé"
        assert len("ééé".encode()) == 6

    def test_truncate_walks_a_structure_and_preserves_shape(self):
        value = {"a": "abcdefgh", "b": [{"c": "abcdefgh"}], "d": 12345, "e": None}
        out = truncate(value, 4)
        assert out == {
            "a": "abcd" + TRUNCATION_MARKER,
            "b": [{"c": "abcd" + TRUNCATION_MARKER}],
            "d": 12345,
            "e": None,
        }

    def test_no_limit_is_a_passthrough(self):
        value = {"a": "abcdefgh"}
        assert truncate(value, None) == value


class TestFilterConfig:
    def test_an_absent_filter_defaults_to_empty(self, base_config):
        config = Config.model_validate(base_config)
        source = config.source_by_name("github")
        assert source.filter.event_types is None
        assert source.filter.require == {}
        assert source.filter.deny == {}
        assert source.filter.max_field_bytes is None

    def test_an_empty_allowlist_is_a_config_error(self, base_config, write_config):
        from webhook_doorman.config import load_config

        base_config["sources"][0]["filter"] = {"event_types": []}
        with pytest.raises(ConfigError) as excinfo:
            load_config(write_config(base_config))
        assert "admit nothing" in str(excinfo.value)

    def test_an_empty_value_list_is_a_config_error(self, base_config, write_config):
        from webhook_doorman.config import load_config

        base_config["sources"][0]["filter"] = {"require": {"issue.state": []}}
        with pytest.raises(ConfigError) as excinfo:
            load_config(write_config(base_config))
        assert "never match" in str(excinfo.value)

    def test_a_non_positive_cap_is_a_config_error(self, base_config, write_config):
        from webhook_doorman.config import load_config

        base_config["sources"][0]["filter"] = {"max_field_bytes": 0}
        with pytest.raises(ConfigError):
            load_config(write_config(base_config))

    def test_an_unknown_filter_key_is_a_config_error(self, base_config, write_config):
        from webhook_doorman.config import load_config

        base_config["sources"][0]["filter"] = {"event_typos": ["push"]}
        with pytest.raises(ConfigError):
            load_config(write_config(base_config))


BODY = json.dumps(PAYLOAD).encode()


def github_headers(body: bytes, delivery: str = "d-1") -> dict[str, str]:
    return {
        "X-Hub-Signature-256": sign_hex(GITHUB_SECRET, body, "sha256="),
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
    }


def build(config_data: dict, env: dict, captured: list):
    async def ingest(event):
        captured.append(event)
        return {"status": "accepted", "event_id": 1}

    app = create_app(config=Config.model_validate(config_data), env=env, ingest=ingest)
    return TestClient(app, client=("127.0.0.1", 51234))


class TestFilterThroughTheApp:
    def test_a_refused_event_carries_the_filtered_status_and_no_sinks(self, base_config, base_env):
        base_config["sources"][0]["filter"] = {"event_types": ["push"]}
        captured: list = []
        client = build(base_config, base_env, captured)

        response = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))

        assert response.status_code == 200
        assert len(captured) == 1
        assert captured[0].status is EventStatus.FILTERED
        assert captured[0].filter_reason == "event_type"
        assert captured[0].sinks == []

    def test_an_admitted_event_is_unchanged(self, base_config, base_env):
        base_config["sources"][0]["filter"] = {"event_types": ["issues.opened"]}
        captured: list = []
        client = build(base_config, base_env, captured)

        client.post("/webhook/github", content=BODY, headers=github_headers(BODY))

        assert captured[0].status is EventStatus.RECEIVED
        assert captured[0].filter_reason is None
        assert captured[0].sinks == ["notes"]

    def test_the_cap_applies_to_summary_and_context_but_not_payload(self, base_config, base_env):
        """`payload` is re-derived from the stored body on every read.

        Capping it here and not the body would make two views of one event disagree, and capping
        the body changes what a replay delivers. So the cap lands on the two fields that are
        stored in their own right.
        """
        base_config["sources"][0]["filter"] = {"max_field_bytes": 8}
        captured: list = []
        client = build(base_config, base_env, captured)

        client.post("/webhook/github", content=BODY, headers=github_headers(BODY))

        event = captured[0]
        assert event.summary.endswith(TRUNCATION_MARKER)
        assert event.context["title"] == "Somethin" + TRUNCATION_MARKER
        assert event.payload["issue"]["title"] == "Something broke"

    def test_an_unfiltered_source_is_byte_identical_to_v0_3_0(self, base_config, base_env):
        """The regression guard: no `filter` key means no observable change at all."""
        captured: list = []
        client = build(base_config, base_env, captured)

        response = client.post("/webhook/github", content=BODY, headers=github_headers(BODY))

        assert response.status_code == 200
        event = captured[0]
        assert event.status is EventStatus.RECEIVED
        assert event.sinks == ["notes"]
        assert event.summary == "[o/r#7] Something broke"
        assert event.context["title"] == "Something broke"


class TestFilterMetric:
    def test_labels_are_bounded_to_the_closed_reason_set(self):
        """The offending value is producer-controlled and must never become a label."""
        METRICS.reset()
        METRICS.initialise(sources={"github": "hmac_sha256"}, sinks=["notes"])
        rendered = METRICS.render(version="test")

        for reason in FILTER_REASONS:
            assert (
                f'webhook_doorman_events_filtered_total{{reason="{reason}",source="github"}} 0'
                in rendered
            )
        assert rendered.count("webhook_doorman_events_filtered_total{") == len(FILTER_REASONS)
        METRICS.reset()

    def test_the_reason_vocabulary_is_one_roster(self):
        """`metrics.FILTER_REASONS` is `filtering.FILTER_REASONS`, not a copy of it."""
        from webhook_doorman import filtering, metrics

        assert metrics.FILTER_REASONS is filtering.FILTER_REASONS


ENGINE_CONFIG: dict = {
    "delivery": {"poll_interval_seconds": 3600},
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
            "url": "https://sink.example.invalid/notes",
            "template": '{"text": "{{ summary }}"}',
        }
    ],
}


@pytest.fixture
async def engine(tmp_path):
    from webhook_doorman.engine import Engine
    from webhook_doorman.secrets import resolve
    from webhook_doorman.store import SqliteStore

    resolved = resolve(
        Config.model_validate(ENGINE_CONFIG), {"INTERNAL_TOKEN": "internal-token-0123456789ab"}
    )
    eng = Engine(resolved, store=SqliteStore(tmp_path / "filtered.db"))
    await eng.start()
    yield eng
    await eng.stop()


def filtered_event(**kwargs):
    from webhook_doorman.models import InboundEvent

    defaults = dict(
        source="internal",
        delivery_id="f-1",
        event_type="issues.opened",
        summary="a summary",
        headers={},
        body=b'{"ok": true}',
        payload={"ok": True},
        sinks=[],
        status=EventStatus.FILTERED,
        filter_reason="event_type",
    )
    defaults.update(kwargs)
    return InboundEvent(**defaults)


class TestFilteredEventIsStored:
    async def test_it_is_persisted_with_the_filtered_status(self, engine):
        result = await engine.ingest(filtered_event())
        assert result["status"] == "filtered"
        assert result["reason"] == "event_type"

        stored = await engine.store.get_event(result["event_id"])
        assert stored is not None
        assert stored.status is EventStatus.FILTERED

    async def test_it_queues_no_deliveries(self, engine):
        """The claim that matters. A predicate returning False proves nothing on its own."""
        result = await engine.ingest(filtered_event())

        cursor = await engine.store.db.execute(
            "SELECT COUNT(*) AS n FROM deliveries WHERE event_id = ?", (result["event_id"],)
        )
        assert int((await cursor.fetchone())["n"]) == 0
        assert await engine.run_once() == 0

    async def test_it_still_counts_as_received(self, engine):
        """A filtered event is stored, so it is received. The two counters answer different
        questions and conflating them would hide the filter's own volume."""
        METRICS.reset()
        await engine.ingest(filtered_event())
        rendered = METRICS.render(version="test")
        assert 'webhook_doorman_events_received_total{source="internal"} 1' in rendered
        assert (
            'webhook_doorman_events_filtered_total{reason="event_type",source="internal"} 1'
            in rendered
        )
        METRICS.reset()

    async def test_a_duplicate_does_not_count_twice(self, engine):
        """Counted after the dedup check: a producer retrying a refused delivery must not
        inflate the filtered total, or the metric measures retries rather than events."""
        METRICS.reset()
        await engine.ingest(filtered_event())
        second = await engine.ingest(filtered_event())

        assert second["deduplicated"] is True
        rendered = METRICS.render(version="test")
        assert (
            'webhook_doorman_events_filtered_total{reason="event_type",source="internal"} 1'
            in rendered
        )
        METRICS.reset()

    async def test_an_unfiltered_event_still_dispatches(self, engine):
        """Regression guard at the engine boundary."""
        result = await engine.ingest(
            filtered_event(
                delivery_id="ok-1", sinks=["notes"], status=EventStatus.RECEIVED, filter_reason=None
            )
        )
        assert result["status"] == "accepted"
        cursor = await engine.store.db.execute(
            "SELECT COUNT(*) AS n FROM deliveries WHERE event_id = ?", (result["event_id"],)
        )
        assert int((await cursor.fetchone())["n"]) == 1
