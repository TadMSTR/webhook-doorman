"""Parsers. Emphasis on malformed payloads — a parser that raises turns a cosmetic
upstream change into a rejected delivery."""

from __future__ import annotations

import json

import pytest

from webhook_doorman.errors import ConfigError
from webhook_doorman.parsers import get_parser, parse, register_parser


def gh(payload: dict, event: str = "issues"):
    return parse("github", json.dumps(payload).encode(), {"x-github-event": event})


class TestGithubParser:
    def test_opened_issue_is_actionable(self):
        result = gh(
            {
                "action": "opened",
                "issue": {
                    "number": 7,
                    "title": "Broken",
                    "html_url": "https://example.invalid/7",
                    "user": {"login": "octocat"},
                    "body": "  details  ",
                },
                "repository": {"full_name": "o/r"},
            }
        )
        assert result.actionable
        assert result.event_type == "issues.opened"
        assert result.summary == "[o/r#7] Broken"
        assert result.context["author"] == "octocat"
        assert result.context["body"] == "details"
        assert result.context["kind"] == "issue"

    def test_opened_pull_request_is_actionable(self):
        result = gh(
            {
                "action": "opened",
                "pull_request": {"number": 3, "title": "Fix", "user": {"login": "dev"}},
                "repository": {"full_name": "o/r"},
            },
            event="pull_request",
        )
        assert result.actionable
        assert result.context["kind"] == "PR"

    def test_closed_issue_is_acknowledged_but_not_actionable(self):
        result = gh({"action": "closed", "issue": {"number": 7}})
        assert not result.actionable
        assert result.event_type == "issues.closed"

    def test_ping_is_acknowledged(self):
        result = gh({}, event="ping")
        assert not result.actionable
        assert result.event_type == "ping"

    def test_missing_repository_falls_back(self):
        result = gh({"action": "opened", "issue": {"number": 1, "user": {}}})
        assert result.summary.startswith("[unknown/unknown#1]")

    def test_null_body_does_not_raise(self):
        result = gh({"action": "opened", "issue": {"number": 1, "body": None}, "repository": {}})
        assert result.context["body"] == ""

    def test_non_dict_payload_is_not_actionable(self):
        result = parse("github", b"[1, 2, 3]", {"x-github-event": "issues"})
        assert not result.actionable

    def test_non_json_body_is_not_actionable(self):
        result = parse("github", b"not json at all", {"x-github-event": "issues"})
        assert not result.actionable

    def test_nested_field_of_wrong_type_does_not_raise(self):
        result = gh(
            {"action": "opened", "issue": {"number": 1, "user": "a-string"}, "repository": []}
        )
        assert result.context["author"] == "unknown"


class TestGenericParser:
    def test_uses_an_event_field_when_present(self):
        result = parse("generic", json.dumps({"event": "build.finished"}).encode(), {})
        assert result.event_type == "build.finished"

    def test_falls_back_to_a_header(self):
        result = parse("generic", b"{}", {"x-event-type": "alert"})
        assert result.event_type == "alert"

    def test_defaults_when_nothing_identifies_the_event(self):
        assert parse("generic", b"{}", {}).event_type == "webhook"

    def test_non_json_body_is_still_an_event(self):
        result = parse("generic", b"<xml/>", {})
        assert result.actionable
        assert result.event_type == "webhook"

    def test_ignores_a_non_string_event_field(self):
        assert parse("generic", json.dumps({"event": 42}).encode(), {}).event_type == "webhook"


class TestVikunjaParser:
    @staticmethod
    def vk(payload: dict):
        return parse("vikunja", json.dumps(payload).encode(), {})

    def test_task_created(self):
        result = self.vk({"event_name": "task.created", "data": {"task": {"id": 3, "title": "T"}}})
        assert result.event_type == "task.created"
        assert "T" in result.summary
        assert result.context["task_id"] == 3

    def test_completion_arrives_as_task_updated_with_done_true(self):
        """There is no task.done event in Vikunja — this is the shape completion actually has."""
        result = self.vk(
            {"event_name": "task.updated", "data": {"task": {"id": 3, "title": "T", "done": True}}}
        )
        assert result.event_type == "task.done"
        assert result.summary == "Task completed: T"

    def test_an_ordinary_update_is_not_reported_as_done(self):
        result = self.vk(
            {"event_name": "task.updated", "data": {"task": {"id": 3, "title": "T", "done": False}}}
        )
        assert result.event_type == "task.updated"

    def test_comment_names_the_author(self):
        result = self.vk(
            {
                "event_name": "task.comment.created",
                "data": {"task": {"title": "T"}, "comment": {"author": {"username": "ann"}}},
            }
        )
        assert "ann" in result.summary

    def test_comment_without_an_author_does_not_raise(self):
        result = self.vk({"event_name": "task.comment.created", "data": {"task": {"title": "T"}}})
        assert "someone" in result.summary

    def test_missing_data_does_not_raise(self):
        assert self.vk({"event_name": "task.created"}).summary.endswith("(untitled)")

    def test_non_dict_payload_is_not_actionable(self):
        assert not parse("vikunja", b"[1]", {}).actionable


class TestGrafanaParser:
    @staticmethod
    def gf(payload: dict):
        return parse("grafana", json.dumps(payload).encode(), {})

    def test_firing_alert(self):
        result = self.gf(
            {
                "status": "firing",
                "title": "Disk almost full",
                "alerts": [{"status": "firing"}, {"status": "firing"}],
            }
        )
        assert result.event_type == "grafana.firing"
        assert result.summary.startswith("[FIRING] Disk almost full")
        assert result.context["firing_count"] == 2

    def test_resolved_alert(self):
        result = self.gf({"status": "resolved", "title": "Disk almost full"})
        assert result.summary.startswith("[RESOLVED]")

    def test_falls_back_to_common_labels_for_a_title(self):
        result = self.gf({"status": "firing", "commonLabels": {"alertname": "HighLatency"}})
        assert "HighLatency" in result.summary

    def test_falls_back_to_the_first_alert_label(self):
        result = self.gf({"status": "firing", "alerts": [{"labels": {"alertname": "FromAlert"}}]})
        assert "FromAlert" in result.summary

    def test_message_is_appended_when_present(self):
        result = self.gf({"status": "firing", "title": "T", "message": "details here"})
        assert result.summary == "[FIRING] T — details here"

    def test_annotation_summary_is_used_when_message_is_absent(self):
        result = self.gf(
            {"status": "firing", "title": "T", "commonAnnotations": {"summary": "from annotation"}}
        )
        assert "from annotation" in result.summary

    def test_an_empty_payload_does_not_raise(self):
        """Every Grafana field is optional in practice. A thin summary beats a rejected delivery."""
        result = self.gf({})
        assert result.actionable
        assert result.summary == "[UNKNOWN] Grafana alert"

    def test_alerts_of_the_wrong_type_do_not_raise(self):
        result = self.gf({"status": "firing", "alerts": "not-a-list"})
        assert result.context["alert_count"] == 0

    def test_non_dict_payload_is_not_actionable(self):
        assert not parse("grafana", b'"a string"', {}).actionable


class TestRegistry:
    def test_unknown_parser_raises_config_error(self):
        with pytest.raises(ConfigError, match="unknown parser"):
            get_parser("does-not-exist")

    def test_registered_parser_is_available(self):
        from webhook_doorman.parsers import _PARSERS, ParsedEvent

        register_parser("temp-test", lambda payload, headers: ParsedEvent("t", "s"))
        try:
            assert parse("temp-test", b"{}", {}).event_type == "t"
        finally:
            _PARSERS.pop("temp-test", None)
