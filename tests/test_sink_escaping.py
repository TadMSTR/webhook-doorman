"""Escaping is a property of the destination's rendering context, not of the data.

Audit `forge-webhook-router-2026-08` filed a Medium against the first version of this code: a
GitHub issue title or body — attacker-controlled on a public repo — reached a Vikunja task
description unescaped, where it is rendered as rich text. That is stored XSS against whoever
opens the task.

It is a recurrence. `vikunja-webhook-listener` had the identical defect (F-1,
`audit-vikunja-migration-2026-07`) and fixed it with `html.escape()`. Porting that service to a
template-rendered sink dropped the fix, because escaping had been a property of the *parser* and
the parser is now shared with sinks whose output is plain text.

So the fix belongs where the rendering context is known: the sink. These tests assert both
halves — escaped where the destination renders HTML, and **not** escaped where it does not,
because an over-broad fix that HTML-escapes chat messages is its own bug.
"""

from __future__ import annotations

import json

import httpx
import pytest

from webhook_doorman.config import HttpSink, MatrixSink, NtfySink, VikunjaTaskSink
from webhook_doorman.sinks import build_sink

XSS_TITLE = '<script>alert("xss")</script>'
XSS_BODY = '<img src=x onerror="alert(1)">'

CONTEXT = {
    "source": "github",
    "summary": f"[o/r#7] {XSS_TITLE}",
    "delivery_id": "d-1",
    "title": XSS_TITLE,
    "body": XSS_BODY,
    "author": "mallory",
    "payload": {"issue": {"title": XSS_TITLE, "body": XSS_BODY}},
}


@pytest.fixture
async def client():
    async with httpx.AsyncClient(timeout=5) as c:
        yield c


def vikunja_sink(**overrides):
    spec = VikunjaTaskSink.model_validate(
        {
            "name": "tickets",
            "type": "vikunja_task",
            "url": "https://tasks.example.invalid",
            "token_env": "VIKUNJA_TOKEN",
            "project_id": 7,
            **overrides,
        }
    )
    return build_sink(spec, {"VIKUNJA_TOKEN": "abcdefgh12345678"})


class TestVikunjaDescriptionIsEscaped:
    """The description is rendered as HTML by Vikunja. Everything interpolated into it escapes."""

    async def test_default_description_template_escapes_a_script_tag(self, client, httpx_mock):
        httpx_mock.add_response(status_code=201)
        await vikunja_sink().deliver(CONTEXT, client)

        description = json.loads(httpx_mock.get_requests()[0].read())["description"]
        assert "<script>" not in description
        assert "&lt;script&gt;" in description

    async def test_an_interpolated_payload_field_escapes(self, client, httpx_mock):
        """The shape the shipped example used to demonstrate."""
        httpx_mock.add_response(status_code=201)
        sink = vikunja_sink(description_template="{{ payload.issue.body | default('') }}")
        await sink.deliver(CONTEXT, client)

        description = json.loads(httpx_mock.get_requests()[0].read())["description"]
        # Assert on the angle brackets, not on the substring `onerror=`. The latter survives as
        # inert text inside a fully-escaped string and testing for its absence would be testing
        # the wrong property — what makes the payload harmless is that there is no tag for the
        # attribute to attach to.
        assert "<" not in description
        assert "&lt;img" in description

    async def test_an_event_handler_attribute_cannot_survive(self, client, httpx_mock):
        httpx_mock.add_response(status_code=201)
        sink = vikunja_sink(description_template="<p>{{ body }}</p>")
        await sink.deliver(CONTEXT, client)

        description = json.loads(httpx_mock.get_requests()[0].read())["description"]
        # The template's own markup is literal template text and is left alone; only the
        # interpolated value is escaped. That distinction is the whole point of autoescape.
        assert description.startswith("<p>")
        assert description.endswith("</p>")
        assert '<img src=x onerror="alert(1)">' not in description

    async def test_operator_markup_in_the_template_still_renders(self, client, httpx_mock):
        httpx_mock.add_response(status_code=201)
        sink = vikunja_sink(description_template='<a href="https://example.invalid">link</a>')
        await sink.deliver(CONTEXT, client)

        description = json.loads(httpx_mock.get_requests()[0].read())["description"]
        assert description == '<a href="https://example.invalid">link</a>'


class TestVikunjaTitleIsNotEscaped:
    """The title is a plain-text field, so escaping it would show literal entities.

    This is the same split the prior fix in `vikunja-webhook-listener` settled on. It is a
    deliberate decision rather than an oversight: an ampersand in an issue title is common, and
    rendering it as `&amp;` in every task title is a visible, everyday bug. If Vikunja ever
    renders titles as rich text this must flip — one call site, in `VikunjaTaskSink_.deliver`.
    """

    async def test_ampersand_in_a_title_is_not_mangled(self, client, httpx_mock):
        httpx_mock.add_response(status_code=201)
        await vikunja_sink().deliver({**CONTEXT, "summary": "Fix A & B"}, client)

        title = json.loads(httpx_mock.get_requests()[0].read())["title"]
        assert title == "Fix A & B"


class TestTextSinksAreNotEscaped:
    """Escaping chat output would be an over-broad fix and a bug in its own right."""

    async def test_matrix_message_is_not_html_escaped(self, client, httpx_mock):
        httpx_mock.add_response(status_code=200)
        spec = MatrixSink.model_validate(
            {
                "name": "chat",
                "type": "matrix",
                "url": "https://matrix.example.invalid",
                "token_env": "MATRIX_TOKEN",
                "room_env": "MATRIX_ROOM",
            }
        )
        sink = build_sink(spec, {"MATRIX_TOKEN": "t" * 16, "MATRIX_ROOM": "!r:example.invalid"})
        await sink.deliver({**CONTEXT, "summary": "Fix A & B < C"}, client)

        body = json.loads(httpx_mock.get_requests()[0].read())["body"]
        assert body == "Fix A & B < C"

    async def test_ntfy_message_is_not_html_escaped(self, client, httpx_mock):
        httpx_mock.add_response(status_code=200)
        spec = NtfySink.model_validate(
            {
                "name": "push",
                "type": "ntfy",
                "url": "https://ntfy.example.invalid",
                "topic_env": "NTFY_TOPIC",
            }
        )
        sink = build_sink(spec, {"NTFY_TOPIC": "alerts"})
        await sink.deliver({**CONTEXT, "summary": "Fix A & B < C"}, client)

        assert httpx_mock.get_requests()[0].read() == b"Fix A & B < C"

    async def test_generic_http_json_body_is_not_html_escaped(self, client, httpx_mock):
        """HTML-escaping a JSON body would corrupt it. JSON has its own escaping, and Jinja's
        `tojson` filter is the documented way to reach it."""
        httpx_mock.add_response(status_code=200)
        spec = HttpSink.model_validate(
            {
                "name": "ops",
                "type": "http",
                "url": "https://ops.example.invalid",
                "template": '{"text": {{ summary | tojson }}}',
            }
        )
        await build_sink(spec, {}).deliver({**CONTEXT, "summary": "Fix A & B"}, client)

        assert json.loads(httpx_mock.get_requests()[0].read())["text"] == "Fix A & B"


class TestEscapeFilterIsAvailableToOperators:
    """An `http` sink pointed at an HTML destination needs a way to opt in."""

    def test_the_e_filter_works_in_the_text_environment(self):
        from webhook_doorman.templating import render

        assert (
            render("{{ title | e }}", CONTEXT)
            == "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;"
        )

    def test_tojson_is_available_for_json_bodies(self):
        from webhook_doorman.templating import render

        assert render("{{ summary | tojson }}", {"summary": 'a "quoted" value'}) == (
            '"a \\"quoted\\" value"'
        )
