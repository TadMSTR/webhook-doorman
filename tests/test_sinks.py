"""Sinks and templating."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from webhook_doorman.config import (
    AppriseSink,
    DiscordSink,
    HttpSink,
    MatrixSink,
    NtfySink,
    SlackSink,
    VikunjaTaskSink,
)
from webhook_doorman.errors import ConfigError, PermanentSinkError, SinkError
from webhook_doorman.sinks import build_sink
from webhook_doorman.sinks.base import parse_retry_after
from webhook_doorman.templating import render, validate

CONTEXT = {
    "source": "github",
    "summary": "[o/r#7] Something broke",
    "delivery_id": "d-1",
    "payload": {"issue": {"title": "Something broke"}},
}


@pytest.fixture
async def client():
    async with httpx.AsyncClient(timeout=5) as c:
        yield c


class TestTemplating:
    def test_renders_context_variables(self):
        assert render("{{ summary }}", CONTEXT) == "[o/r#7] Something broke"

    def test_renders_a_nested_payload_field(self):
        assert render("{{ payload.issue.title }}", CONTEXT) == "Something broke"

    def test_missing_variable_renders_empty_rather_than_raising(self):
        """A producer that stops sending an optional field must not turn every delivery into
        a retry loop."""
        assert render("[{{ nope }}]", CONTEXT) == "[]"

    def test_missing_nested_field_renders_empty(self):
        assert render("[{{ payload.absent.deeper }}]", CONTEXT) == "[]"

    def test_malformed_template_is_permanent(self):
        with pytest.raises(PermanentSinkError):
            render("{% for %}", CONTEXT)

    def test_validate_catches_a_bad_template_without_rendering(self):
        with pytest.raises(PermanentSinkError):
            validate("{{ unclosed ")

    def test_sandbox_blocks_attribute_escape(self):
        """No route from a template to the interpreter. This is why there is no scripting
        engine: the sandbox is a boundary to hold, not a feature to extend."""
        with pytest.raises(PermanentSinkError):
            render("{{ ''.__class__.__mro__[1].__subclasses__() }}", CONTEXT)

    def test_sandbox_blocks_dunder_access_on_context_objects(self):
        """The sandbox refuses the attribute and yields undefined, which renders empty.

        Blocked, not raised — worth asserting on the output rather than on an exception, because
        an implementation that quietly returned the real `__class__` would also not raise.
        """
        assert render("[{{ payload.__class__ }}]", CONTEXT) == "[]"
        assert render("[{{ payload.__class__.__name__ }}]", CONTEXT) == "[]"


class TestHttpSink:
    @staticmethod
    def sink(**overrides):
        spec = HttpSink.model_validate(
            {
                "name": "notes",
                "type": "http",
                "url": "https://sink.example.invalid/notes",
                "template": '{"text": "{{ summary }}"}',
                **overrides,
            }
        )
        return build_sink(spec, {})

    async def test_posts_the_rendered_body(self, client, httpx_mock):
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=204)
        outcome = await self.sink().deliver(CONTEXT, client)
        assert outcome.response_code == 204
        assert httpx_mock.get_requests()[0].read() == b'{"text": "[o/r#7] Something broke"}'

    async def test_a_redirect_is_permanent_not_a_silent_success(self, client, httpx_mock):
        """A 3xx delivers nothing, because the engine does not follow redirects.

        The engine sets `follow_redirects=False` deliberately — a webhook URL embeds its own
        credential. So an operator who typed `http://` against an instance that redirects to
        `https://` gets a sink that notifies nobody, and before this it was recorded as a
        successful delivery: no retry, no DLQ row, nothing above debug.
        """
        httpx_mock.add_response(
            url="https://sink.example.invalid/notes",
            status_code=301,
            headers={"Location": "https://sink.example.invalid/moved"},
        )
        with pytest.raises(PermanentSinkError, match="redirected") as exc:
            await self.sink().deliver(CONTEXT, client)
        assert "https://sink.example.invalid/moved" in str(exc.value)

    async def test_a_redirect_without_a_location_still_fails(self, client, httpx_mock):
        """`Location` is destination-controlled, so its absence must not break the message."""
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=302)
        with pytest.raises(PermanentSinkError, match="redirected"):
            await self.sink().deliver(CONTEXT, client)

    async def test_invalid_rendered_json_is_permanent(self, client):
        """Catch it here rather than reading the destination's 400 back as an opaque failure."""
        sink = self.sink(template='{"text": {{ summary }}}')
        with pytest.raises(PermanentSinkError, match="invalid JSON"):
            await sink.deliver(CONTEXT, client)

    async def test_non_json_content_type_skips_the_json_check(self, client, httpx_mock):
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=200)
        sink = self.sink(content_type="text/plain", template="{{ summary }}")
        assert (await sink.deliver(CONTEXT, client)).response_code == 200

    async def test_extra_headers_are_sent(self, client, httpx_mock):
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=200)
        await self.sink(headers={"X-Trace": "abc"}).deliver(CONTEXT, client)
        assert httpx_mock.get_requests()[0].headers["x-trace"] == "abc"

    async def test_token_env_becomes_a_bearer_header(self, client, httpx_mock):
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=200)
        spec = HttpSink.model_validate(
            {
                "name": "notes",
                "type": "http",
                "url": "https://sink.example.invalid/notes",
                "token_env": "SINK_TOKEN",
            }
        )
        sink = build_sink(spec, {"SINK_TOKEN": "abcdefgh12345678"})
        await sink.deliver(CONTEXT, client)
        assert httpx_mock.get_requests()[0].headers["authorization"] == "Bearer abcdefgh12345678"

    async def test_unset_url_env_is_permanent(self, client):
        spec = HttpSink.model_validate({"name": "n", "type": "http", "url_env": "SINK_URL"})
        with pytest.raises(PermanentSinkError, match="SINK_URL is unset"):
            await build_sink(spec, {}).deliver(CONTEXT, client)

    async def test_url_env_is_used_when_set(self, client, httpx_mock):
        httpx_mock.add_response(url="https://from-env.example.invalid", status_code=200)
        spec = HttpSink.model_validate({"name": "n", "type": "http", "url_env": "SINK_URL"})
        sink = build_sink(spec, {"SINK_URL": "https://from-env.example.invalid"})
        assert (await sink.deliver(CONTEXT, client)).response_code == 200

    async def test_transport_error_is_retryable(self, client, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)


class TestMatrixSink:
    @staticmethod
    def sink(secrets):
        spec = MatrixSink.model_validate(
            {
                "name": "chat",
                "type": "matrix",
                "url": "https://matrix.example.invalid",
                "token_env": "MATRIX_TOKEN",
                "room_env": "MATRIX_ROOM",
            }
        )
        return build_sink(spec, secrets)

    async def test_puts_a_message_into_the_room(self, client, httpx_mock):
        httpx_mock.add_response(status_code=200)
        sink = self.sink(
            {"MATRIX_TOKEN": "syt-not-real-token", "MATRIX_ROOM": "!room:example.invalid"}
        )
        await sink.deliver(CONTEXT, client)
        request = httpx_mock.get_requests()[0]
        assert request.method == "PUT"
        assert "/_matrix/client/v3/rooms/" in str(request.url)
        assert b"Something broke" in request.read()

    async def test_room_id_is_url_encoded(self, client, httpx_mock):
        """A room ID starts with '!' and contains ':' — both need escaping in a path segment."""
        httpx_mock.add_response(status_code=200)
        sink = self.sink({"MATRIX_TOKEN": "t" * 16, "MATRIX_ROOM": "!abc:example.invalid"})
        await sink.deliver(CONTEXT, client)
        assert "%21abc%3Aexample.invalid" in str(httpx_mock.get_requests()[0].url)

    async def test_unset_credentials_are_permanent(self, client):
        with pytest.raises(PermanentSinkError):
            await self.sink({}).deliver(CONTEXT, client)


class TestNtfySink:
    async def test_posts_to_the_topic_with_a_title(self, client, httpx_mock):
        httpx_mock.add_response(url="https://ntfy.example.invalid/alerts", status_code=200)
        spec = NtfySink.model_validate(
            {
                "name": "push",
                "type": "ntfy",
                "url": "https://ntfy.example.invalid",
                "topic_env": "NTFY_TOPIC",
            }
        )
        await build_sink(spec, {"NTFY_TOPIC": "alerts"}).deliver(CONTEXT, client)
        request = httpx_mock.get_requests()[0]
        assert request.headers["Title"] == "github"
        assert request.read() == b"[o/r#7] Something broke"

    async def test_unset_topic_is_permanent(self, client):
        spec = NtfySink.model_validate(
            {"name": "push", "type": "ntfy", "url": "https://x.example.invalid", "topic_env": "T"}
        )
        with pytest.raises(PermanentSinkError):
            await build_sink(spec, {}).deliver(CONTEXT, client)


class TestNtfyNonAsciiTitle:
    """An em-dash in a title used to crash the sink and burn all five attempts.

    Not an edge case: em-dashes, curly quotes, accented names and emoji are ordinary in real
    Vikunja task titles, and the failure was quiet because the same event's Matrix sink
    delivered fine. Reported as vikunja#446 against v0.1.0.
    """

    @staticmethod
    def sink():
        spec = NtfySink.model_validate(
            {
                "name": "push",
                "type": "ntfy",
                "url": "https://ntfy.example.invalid",
                "topic_env": "NTFY_TOPIC",
                "title_template": "{{ summary }}",
            }
        )
        return build_sink(spec, {"NTFY_TOPIC": "alerts"})

    async def test_an_em_dash_title_delivers(self, client, httpx_mock):
        httpx_mock.add_response(url="https://ntfy.example.invalid/alerts", status_code=200)
        context = {**CONTEXT, "summary": "[smoke test] requeue — ignore"}
        assert (await self.sink().deliver(context, client)).response_code == 200

    async def test_the_title_header_is_rfc_2047_encoded(self, client, httpx_mock):
        httpx_mock.add_response(url="https://ntfy.example.invalid/alerts", status_code=200)
        context = {**CONTEXT, "summary": "café — 100% ✅"}
        await self.sink().deliver(context, client)

        title = httpx_mock.get_requests()[0].headers["Title"]
        assert title.startswith("=?UTF-8?B?") and title.endswith("?=")
        # Decode it the way ntfy's server does, and confirm nothing was lost on the way out.
        payload = title.removeprefix("=?UTF-8?B?").removesuffix("?=")
        assert base64.b64decode(payload).decode("utf-8") == "café — 100% ✅"

    async def test_an_ascii_title_is_left_alone(self, client, httpx_mock):
        """Encoding unconditionally would make every title unreadable in a log or a capture."""
        httpx_mock.add_response(url="https://ntfy.example.invalid/alerts", status_code=200)
        await self.sink().deliver({**CONTEXT, "summary": "plain ascii"}, client)
        assert httpx_mock.get_requests()[0].headers["Title"] == "plain ascii"

    async def test_the_body_still_carries_utf8_directly(self, client, httpx_mock):
        """Only headers are ASCII-constrained. The body was never the problem."""
        httpx_mock.add_response(url="https://ntfy.example.invalid/alerts", status_code=200)
        await self.sink().deliver({**CONTEXT, "summary": "body — dash"}, client)
        assert httpx_mock.get_requests()[0].read() == "body — dash".encode()


class TestUnicodeGuard:
    """`HttpSinkBase` treats an encoding failure as terminal — the net under every sink.

    A sink that forgets to encode a header should surface immediately in the DLQ, not five
    attempts and several minutes of backoff later. Plan 2's Discord and Slack sinks inherit this.
    """

    async def test_a_non_ascii_header_is_permanent_not_retryable(self, client):
        spec = HttpSink.model_validate(
            {
                "name": "notes",
                "type": "http",
                "url": "https://sink.example.invalid/notes",
                "headers": {"X-Trace": "café"},
            }
        )
        with pytest.raises(PermanentSinkError, match="cannot encode request"):
            await build_sink(spec, {}).deliver(CONTEXT, client)

    async def test_the_request_is_never_sent(self, client, httpx_mock):
        """httpx raises from inside `request`, so there is nothing on the wire to observe."""
        spec = HttpSink.model_validate(
            {
                "name": "notes",
                "type": "http",
                "url": "https://sink.example.invalid/notes",
                "headers": {"X-Trace": "ünicode"},
            }
        )
        with pytest.raises(PermanentSinkError):
            await build_sink(spec, {}).deliver(CONTEXT, client)
        assert httpx_mock.get_requests() == []


class TestParseRetryAfter:
    """Both RFC 9110 §10.2.3 forms, and the failure directions that matter."""

    def test_delta_seconds(self):
        assert parse_retry_after("7") == 7.0

    def test_delta_seconds_with_surrounding_space(self):
        assert parse_retry_after("  7  ") == 7.0

    def test_fractional_seconds_are_accepted(self):
        """Sub-second rate-limit windows are real; RFC 9110's integer-only form is not a reason
        to throw the value away and wait the full backoff instead."""
        assert parse_retry_after("0.75") == 0.75

    def test_zero_is_a_valid_delay(self):
        assert parse_retry_after("0") == 0.0

    def test_a_negative_delta_is_rejected(self):
        """Not a valid delta-seconds, and reading it as "retry now" would let a destination
        accelerate our retries at itself until the attempt budget is gone."""
        assert parse_retry_after("-5") is None

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf", "infinity", "1e400", "9" * 400])
    def test_non_finite_values_are_rejected(self, value):
        """`float()` accepts all of these. The engine's clamp would contain them today, but a
        parser that can hand back `inf` is one refactor away from an unclamped arithmetic —
        and `_jittered(inf)` is `nan`, which is a delivery that never comes due."""
        assert parse_retry_after(value) is None

    def test_http_date(self):
        now = datetime(2026, 10, 21, 7, 28, 0, tzinfo=UTC)
        assert parse_retry_after("Wed, 21 Oct 2026 07:28:30 GMT", now=now) == 30.0

    def test_an_http_date_in_the_past_is_zero_not_negative(self):
        now = datetime(2026, 10, 21, 7, 30, 0, tzinfo=UTC)
        assert parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", now=now) == 0.0

    @pytest.mark.parametrize("value", [None, "", "   ", "soon", "next tuesday", "7 seconds"])
    def test_unreadable_values_fall_back_to_the_backoff_curve(self, value):
        """`None`, not `0` — garbage must not be able to collapse the retry interval."""
        assert parse_retry_after(value) is None


class TestRetryAfterOnTheWire:
    @staticmethod
    def sink():
        spec = HttpSink.model_validate(
            {"name": "notes", "type": "http", "url": "https://sink.example.invalid/notes"}
        )
        return build_sink(spec, {})

    @pytest.mark.parametrize("code", [429, 503])
    async def test_a_retryable_status_carries_retry_after(self, client, httpx_mock, code):
        httpx_mock.add_response(
            url="https://sink.example.invalid/notes",
            status_code=code,
            headers={"Retry-After": "7"},
        )
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert exc.value.retry_after == 7.0

    async def test_absent_header_leaves_it_unset(self, client, httpx_mock):
        httpx_mock.add_response(url="https://sink.example.invalid/notes", status_code=429)
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert exc.value.retry_after is None

    async def test_a_permanent_failure_carries_no_delay(self, client, httpx_mock):
        """A 400 is not coming back, whatever the destination says about when."""
        httpx_mock.add_response(
            url="https://sink.example.invalid/notes",
            status_code=400,
            headers={"Retry-After": "7"},
        )
        with pytest.raises(PermanentSinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert exc.value.retry_after is None

    async def test_a_transport_error_carries_no_delay(self, client, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert exc.value.retry_after is None


class TestVikunjaTaskSink:
    async def test_creates_a_task_in_the_project(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://tasks.example.invalid/api/v1/projects/7/tasks", status_code=201
        )
        spec = VikunjaTaskSink.model_validate(
            {
                "name": "tickets",
                "type": "vikunja_task",
                "url": "https://tasks.example.invalid",
                "token_env": "VIKUNJA_TOKEN",
                "project_id": 7,
                "title_template": "{{ summary }}",
                "description_template": "from {{ source }}",
            }
        )
        await build_sink(spec, {"VIKUNJA_TOKEN": "abcdefgh12345678"}).deliver(CONTEXT, client)
        request = httpx_mock.get_requests()[0]
        assert request.method == "PUT"
        assert b"Something broke" in request.read()


DISCORD_URL = "https://discord.com/api/webhooks/1/tok"
SLACK_URL = "https://hooks.slack.com/services/T0/B0/xxx"


class TestDiscordSink:
    @staticmethod
    def sink(secrets=None, **overrides):
        spec = DiscordSink.model_validate(
            {
                "name": "team-discord",
                "type": "discord",
                "webhook_url_env": "DISCORD_WEBHOOK_URL",
                **overrides,
            }
        )
        if secrets is None:
            secrets = {"DISCORD_WEBHOOK_URL": DISCORD_URL}
        return build_sink(spec, secrets)

    async def test_posts_the_rendered_content(self, client, httpx_mock):
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        outcome = await self.sink().deliver(CONTEXT, client)
        assert outcome.response_code == 204
        assert json.loads(httpx_mock.get_requests()[0].read())["content"] == (
            "[o/r#7] Something broke"
        )

    async def test_unset_webhook_url_env_is_permanent(self, client):
        with pytest.raises(PermanentSinkError, match="DISCORD_WEBHOOK_URL is unset"):
            await self.sink(secrets={}).deliver(CONTEXT, client)

    async def test_transport_error_is_retryable(self, client, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)

    async def test_allowed_mentions_is_present_on_every_request(self, client, httpx_mock):
        """Not on the default template only — on every request this sink can be made to send.

        A test that only checks the default would pass an implementation that dropped
        `allowed_mentions` whenever any optional field was set.
        """
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        httpx_mock.add_response(url=f"{DISCORD_URL}?thread_id=42", status_code=204)

        await self.sink().deliver(CONTEXT, client)
        await self.sink(username="doorman", avatar_url="https://x.example/a.png").deliver(
            CONTEXT, client
        )
        await self.sink(thread_id="42").deliver(CONTEXT, client)

        for request in httpx_mock.get_requests():
            assert json.loads(request.read())["allowed_mentions"] == {"parse": []}

    async def test_an_everyone_mention_in_the_summary_cannot_resolve(self, client, httpx_mock):
        """The payload field is attacker-authored on any public repo.

        The `@everyone` text survives in `content` — Discord shows it as literal text — and
        that is correct. What must not survive is its *resolution*, which `allowed_mentions`
        governs. Asserting the text is gone would be asserting the wrong fix.
        """
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        await self.sink().deliver({**CONTEXT, "summary": "@everyone pwned"}, client)

        body = json.loads(httpx_mock.get_requests()[0].read())
        assert body["content"] == "@everyone pwned"
        assert body["allowed_mentions"] == {"parse": []}

    async def test_an_over_long_body_is_truncated_rather_than_400d(self, client, httpx_mock):
        """Discord answers 400 over 2000 characters, and 400 is permanent — straight to the DLQ.

        An ordinary long release-notes payload would hit this, so truncation is the difference
        between a slightly short message and a lost one.
        """
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        await self.sink().deliver({**CONTEXT, "summary": "x" * 5000}, client)

        content = json.loads(httpx_mock.get_requests()[0].read())["content"]
        assert len(content) <= 2000
        assert content.endswith("…")

    async def test_a_body_at_the_limit_is_left_alone(self, client, httpx_mock):
        """The boundary in the other direction — truncating an exactly-legal message would be
        a silent, permanent corruption of every message that happened to be 2000 long."""
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        await self.sink().deliver({**CONTEXT, "summary": "x" * 2000}, client)

        content = json.loads(httpx_mock.get_requests()[0].read())["content"]
        assert content == "x" * 2000
        assert "…" not in content

    async def test_optional_identity_fields_are_omitted_when_unset(self, client, httpx_mock):
        """An explicit null `username` overrides the webhook's configured name in Discord."""
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        await self.sink().deliver(CONTEXT, client)

        body = json.loads(httpx_mock.get_requests()[0].read())
        assert "username" not in body
        assert "avatar_url" not in body

    async def test_optional_identity_fields_are_sent_when_set(self, client, httpx_mock):
        httpx_mock.add_response(url=DISCORD_URL, status_code=204)
        await self.sink(username="doorman", avatar_url="https://x.example/a.png").deliver(
            CONTEXT, client
        )
        body = json.loads(httpx_mock.get_requests()[0].read())
        assert body["username"] == "doorman"
        assert body["avatar_url"] == "https://x.example/a.png"

    async def test_thread_id_becomes_a_query_parameter(self, client, httpx_mock):
        httpx_mock.add_response(url=f"{DISCORD_URL}?thread_id=42", status_code=204)
        await self.sink(thread_id="42").deliver(CONTEXT, client)
        assert httpx_mock.get_requests()[0].url.params["thread_id"] == "42"

    def test_there_is_no_inline_url_form(self):
        """The URL embeds the token, so an inline form would invite committing a live
        credential — and would keep it out of the redaction set."""
        with pytest.raises(ValidationError):
            DiscordSink.model_validate({"name": "d", "type": "discord", "url": DISCORD_URL})


class TestSlackSink:
    @staticmethod
    def sink(secrets=None, **overrides):
        spec = SlackSink.model_validate(
            {
                "name": "team-slack",
                "type": "slack",
                "webhook_url_env": "SLACK_WEBHOOK_URL",
                **overrides,
            }
        )
        return build_sink(spec, {"SLACK_WEBHOOK_URL": SLACK_URL} if secrets is None else secrets)

    async def test_posts_the_rendered_text(self, client, httpx_mock):
        httpx_mock.add_response(url=SLACK_URL, status_code=200)
        outcome = await self.sink().deliver(CONTEXT, client)
        assert outcome.response_code == 200
        assert json.loads(httpx_mock.get_requests()[0].read()) == {
            "text": "[o/r#7] Something broke"
        }

    async def test_unset_webhook_url_env_is_permanent(self, client):
        with pytest.raises(PermanentSinkError, match="SLACK_WEBHOOK_URL is unset"):
            await self.sink(secrets={}).deliver(CONTEXT, client)

    async def test_transport_error_is_retryable(self, client, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)

    async def test_a_429_carries_retry_after_to_the_engine(self, client, httpx_mock):
        """Slack rate-limits incoming webhooks at roughly one message per second per channel,
        so this is the ordinary path on a burst rather than an exotic one."""
        httpx_mock.add_response(url=SLACK_URL, status_code=429, headers={"Retry-After": "7"})
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)
        # Raw and unclamped: the engine owns the clamp, because a sink cannot see
        # `delivery.max_backoff_seconds`.
        assert exc.value.retry_after == 7.0

    def test_there_is_no_inline_url_form(self):
        with pytest.raises(ValidationError):
            SlackSink.model_validate({"name": "s", "type": "slack", "url": SLACK_URL})


class TestAppriseSink:
    @staticmethod
    def sink(secrets=None, **overrides):
        spec = AppriseSink.model_validate(
            {
                "name": "fanout",
                "type": "apprise",
                "url": "https://apprise.example.invalid",
                "key_env": "APPRISE_KEY",
                **overrides,
            }
        )
        return build_sink(spec, {"APPRISE_KEY": "mykey"} if secrets is None else secrets)

    URL = "https://apprise.example.invalid/notify/mykey"

    async def test_posts_to_the_stateful_key_endpoint(self, client, httpx_mock):
        httpx_mock.add_response(url=self.URL, status_code=200)
        outcome = await self.sink().deliver(CONTEXT, client)
        assert outcome.response_code == 200

        body = json.loads(httpx_mock.get_requests()[0].read())
        assert body["body"] == "[o/r#7] Something broke"
        assert body["title"] == "github"
        assert body["type"] == "info"
        assert body["format"] == "text"

    async def test_no_downstream_urls_are_ever_sent(self, client, httpx_mock):
        """The stateless form would carry every downstream credential in the request body.

        Stateful keeps them in Apprise's own store, which is the whole reason for choosing it.
        """
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink().deliver(CONTEXT, client)
        assert "urls" not in json.loads(httpx_mock.get_requests()[0].read())

    async def test_unset_key_env_is_permanent(self, client):
        with pytest.raises(PermanentSinkError, match="APPRISE_KEY is unset"):
            await self.sink(secrets={}).deliver(CONTEXT, client)

    async def test_transport_error_is_retryable(self, client, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)

    async def test_204_is_permanent_not_a_silent_success(self, client, httpx_mock):
        """The finding this sink exists for.

        `204` is below 400, so the default classification calls it delivered. Apprise means
        "I notified nothing" — an unknown key, or a key whose config has no valid URLs. Read as
        success, a typo'd key swallows every event and the DLQ stays empty.
        """
        httpx_mock.add_response(url=self.URL, status_code=204)
        with pytest.raises(PermanentSinkError, match="notified nothing"):
            await self.sink().deliver(CONTEXT, client)

    async def test_424_is_permanent_deliberately(self, client, httpx_mock):
        """ "At least one notification failed." Retrying re-notifies the ones that succeeded,
        so the DLQ row is the honest outcome. A judgement call, asserted so it stays one."""
        httpx_mock.add_response(url=self.URL, status_code=424)
        with pytest.raises(PermanentSinkError, match="re-notifies"):
            await self.sink().deliver(CONTEXT, client)

    async def test_500_is_still_retryable(self, client, httpx_mock):
        """The override must not swallow the codes it does not know about."""
        httpx_mock.add_response(url=self.URL, status_code=500)
        with pytest.raises(SinkError) as exc:
            await self.sink().deliver(CONTEXT, client)
        assert not isinstance(exc.value, PermanentSinkError)

    async def test_accept_json_is_set(self, client, httpx_mock):
        """So an error response carries a structured `error` field rather than text/plain,
        which is what makes the excerpt in the SinkError message worth reading."""
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink().deliver(CONTEXT, client)
        assert httpx_mock.get_requests()[0].headers["accept"] == "application/json"

    async def test_html_body_format_escapes_the_body(self, client, httpx_mock):
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink(body_format="html").deliver(
            {**CONTEXT, "summary": "<script>alert(1)</script>"}, client
        )
        body = json.loads(httpx_mock.get_requests()[0].read())["body"]
        assert "<script>" not in body
        assert "&lt;script&gt;" in body

    async def test_text_body_format_does_not_escape(self, client, httpx_mock):
        """The other half. Escaping a plain-text notification is corruption, not hardening."""
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink().deliver({**CONTEXT, "summary": "Fix A & B < C"}, client)
        assert json.loads(httpx_mock.get_requests()[0].read())["body"] == "Fix A & B < C"

    async def test_tag_is_omitted_when_unset(self, client, httpx_mock):
        """An empty `tag` is not the same as no tag — Apprise routes on it."""
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink().deliver(CONTEXT, client)
        assert "tag" not in json.loads(httpx_mock.get_requests()[0].read())

    async def test_tag_is_sent_when_set(self, client, httpx_mock):
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink(tag="ops").deliver(CONTEXT, client)
        assert json.loads(httpx_mock.get_requests()[0].read())["tag"] == "ops"

    async def test_notify_type_and_body_format_are_sent(self, client, httpx_mock):
        httpx_mock.add_response(url=self.URL, status_code=200)
        await self.sink(notify_type="warning", body_format="markdown").deliver(CONTEXT, client)
        body = json.loads(httpx_mock.get_requests()[0].read())
        assert body["type"] == "warning"
        assert body["format"] == "markdown"

    async def test_a_key_with_url_metacharacters_is_quoted(self, client, httpx_mock):
        """Assert on `raw_path`, not `path`.

        `path` is a decoded convenience property and reports `/notify/a/../b` even when the
        bytes on the wire are correctly escaped — so a test written against it fails on
        working code, and would pass on broken code if the expectation were flipped to match.
        `raw_path` is what the server actually receives.
        """
        httpx_mock.add_response(status_code=200)
        await self.sink(secrets={"APPRISE_KEY": "a/../b"}).deliver(CONTEXT, client)
        assert httpx_mock.get_requests()[0].url.raw_path == b"/notify/a%2F..%2Fb"


class TestRegistry:
    def test_unknown_spec_type_is_a_config_error(self):
        class Fake:
            name = "x"
            type = "made-up"

        with pytest.raises(ConfigError, match="no implementation"):
            build_sink(Fake(), {})

    def test_a_bad_template_fails_at_build_time_not_delivery_time(self):
        spec = HttpSink.model_validate(
            {
                "name": "n",
                "type": "http",
                "url": "https://x.example.invalid",
                "template": "{% if %}",
            }
        )
        with pytest.raises(PermanentSinkError):
            build_sink(spec, {})
