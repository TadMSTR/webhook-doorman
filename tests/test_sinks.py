"""Sinks and templating."""

from __future__ import annotations

import httpx
import pytest

from webhook_doorman.config import HttpSink, MatrixSink, NtfySink, VikunjaTaskSink
from webhook_doorman.errors import ConfigError, PermanentSinkError, SinkError
from webhook_doorman.sinks import build_sink
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
