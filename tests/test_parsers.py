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
