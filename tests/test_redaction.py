"""Redaction — the control that keeps the event log from becoming a secret store."""

from __future__ import annotations

from webhook_doorman.redaction import (
    REDACTED,
    redact_bytes,
    redact_headers,
    redact_json,
    redact_text,
)

SECRET = "super-secret-token-value-0123456789"


class TestRedactHeaders:
    def test_authorization_redacted_by_name(self):
        out = redact_headers({"authorization": "Bearer anything"})
        assert out["authorization"] == REDACTED

    def test_cookie_redacted_by_name(self):
        assert redact_headers({"cookie": "session=abc"})["cookie"] == REDACTED

    def test_source_credential_header_redacted(self):
        out = redact_headers({"x-custom-sig": "abc"}, extra_headers=["X-Custom-Sig"])
        assert out["x-custom-sig"] == REDACTED

    def test_secret_value_redacted_wherever_it_appears(self):
        out = redact_headers({"x-echo": f"prefix {SECRET} suffix"}, secret_values=[SECRET])
        assert SECRET not in out["x-echo"]
        assert out["x-echo"] == f"prefix {REDACTED} suffix"

    def test_ordinary_headers_survive(self):
        out = redact_headers({"content-type": "application/json"})
        assert out["content-type"] == "application/json"

    def test_input_is_not_mutated(self):
        headers = {"authorization": "Bearer real"}
        redact_headers(headers)
        assert headers["authorization"] == "Bearer real"

    def test_short_secrets_are_not_value_matched(self):
        """A 3-character 'secret' would match everywhere and corrupt the record."""
        out = redact_headers({"x-echo": "abcdef"}, secret_values=["abc"])
        assert out["x-echo"] == "abcdef"

    def test_overlapping_secrets_leave_no_fragment(self):
        long_secret = "aaaaaaaaaa-bbbbbbbbbb"
        short_secret = "aaaaaaaaaa"
        out = redact_headers(
            {"x-echo": f"[{long_secret}]"}, secret_values=[short_secret, long_secret]
        )
        assert "bbbbbbbbbb" not in out["x-echo"]


class TestRedactBody:
    def test_secret_in_body_is_removed(self):
        body = b'{"token": "' + SECRET.encode() + b'"}'
        assert SECRET.encode() not in redact_bytes(body, [SECRET])

    def test_body_without_secrets_is_unchanged(self):
        body = b'{"ok": true}'
        assert redact_bytes(body, [SECRET]) == body

    def test_empty_secret_list_is_a_no_op(self):
        body = b"anything at all"
        assert redact_bytes(body, []) == body


class TestRedactJson:
    def test_nested_string_is_redacted(self):
        data = {"issue": {"body": SECRET, "n": 1}}
        assert redact_json(data, [SECRET]) == {"issue": {"body": REDACTED, "n": 1}}

    def test_list_members_are_redacted(self):
        assert redact_json([SECRET, "safe"], [SECRET]) == [REDACTED, "safe"]

    def test_non_string_scalars_pass_through(self):
        data = {"n": 1, "f": 1.5, "b": True, "z": None}
        assert redact_json(data, [SECRET]) == data

    def test_no_secrets_is_a_no_op(self):
        data = {"a": "b"}
        assert redact_json(data, []) is data


class TestRedactText:
    def test_replaces_every_occurrence(self):
        text = f"{SECRET} and again {SECRET}"
        assert redact_text(text, [SECRET]) == f"{REDACTED} and again {REDACTED}"

    def test_empty_secret_ignored(self):
        assert redact_text("unchanged", ["", None or ""]) == "unchanged"
