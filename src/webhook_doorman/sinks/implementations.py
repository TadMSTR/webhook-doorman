"""The four bundled sinks.

`matrix`, `ntfy` and `vikunja_task` are ported from the listeners this project replaces, minus
their hardcoded endpoint defaults — those were one deployment's topology baked into source, and
carrying them into a public repo is how a homelab's hostnames end up in someone else's traceback.
Every endpoint here comes from config.

`http` is the escape hatch, and it is the reason the other three do not need siblings. A generic
POST with a rendered body covers any destination that speaks JSON, which is most of them. One of
the receivers this replaced existed solely to shell out to a local reindex command; as an `http`
sink it is a config entry.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import quote

import httpx

from ..config import HttpSink, MatrixSink, NtfySink, VikunjaTaskSink
from ..errors import PermanentSinkError
from ..templating import render, render_html, validate
from .base import DeliveryOutcome, HttpSinkBase


def _resolve_url(spec: Any, secrets: dict[str, str]) -> str:
    """A sink's endpoint, from either the inline `url` or the `url_env` reference."""
    if getattr(spec, "url", None):
        return spec.url.rstrip("/")
    value = secrets.get(spec.url_env, "").strip()
    if not value:
        raise PermanentSinkError(f"{spec.name}: {spec.url_env} is unset")
    return value.rstrip("/")


def _encoded_word(value: str) -> str:
    """An HTTP header value safe to send as ASCII, RFC 2047-encoding it only if it has to.

    Header values go out as ASCII — httpx raises `UnicodeEncodeError` from inside
    `client.request` otherwise — but the content rendered into them is event data, and event
    data is full of em-dashes, curly quotes and accented names. ntfy documents RFC 2047
    encoded-words for exactly this (`=?UTF-8?B?<base64>?=`) and decodes them back for display.

    Encoding only when needed is deliberate: an ASCII title stays readable in a packet capture,
    in a server log, and to any tool downstream that has not implemented RFC 2047.
    """
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return f"=?UTF-8?B?{encoded}?="
    return value


class MatrixMessageSink(HttpSinkBase):
    """Post a plain-text message into a Matrix room."""

    def __init__(self, spec: MatrixSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        base = _resolve_url(self.spec, self.secrets)
        token = self.secrets.get(self.spec.token_env, "")
        room = self.secrets.get(self.spec.room_env, "")
        if not token or not room:
            raise PermanentSinkError(f"{self.name}: matrix token or room is unset")

        message = render(self.spec.template, context)
        # A transaction ID makes the send idempotent on the homeserver: a retry after a timeout
        # that actually succeeded is collapsed rather than posted twice.
        txn = f"doorman-{context.get('delivery_id', 'x')}-{int(time.time())}"
        url = (
            f"{base}/_matrix/client/v3/rooms/{quote(room, safe='')}"
            f"/send/m.room.message/{quote(txn, safe='')}"
        )
        return await self._send(
            client,
            "PUT",
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"msgtype": "m.text", "body": message},
        )


class NtfySink_(HttpSinkBase):
    """Publish a push notification to an ntfy topic."""

    def __init__(self, spec: NtfySink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)
        validate(spec.title_template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        base = _resolve_url(self.spec, self.secrets)
        topic = self.secrets.get(self.spec.topic_env, "")
        if not topic:
            raise PermanentSinkError(f"{self.name}: {self.spec.topic_env} is unset")

        headers = {
            "Title": _encoded_word(render(self.spec.title_template, context)),
            "Tags": self.spec.tags,
        }
        if self.spec.token_env:
            token = self.secrets.get(self.spec.token_env, "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        body = render(self.spec.template, context).encode("utf-8")
        return await self._send(
            client, "POST", f"{base}/{quote(topic, safe='')}", headers=headers, content=body
        )


class VikunjaTaskSink_(HttpSinkBase):
    """Create a task in a Vikunja project.

    The only bundled sink whose destination renders rich text, and therefore the only one that
    escapes. The two fields are treated differently on purpose:

    * **`description` renders as HTML** in Vikunja's editor, so it goes through `render_html`
      and every interpolated value is escaped. Without this, an issue body from a public repo
      is stored XSS against whoever opens the task — the exact defect this sink's predecessor
      was audited for and fixed.
    * **`title` is a plain-text field.** Escaping it would put literal `&amp;` in front of every
      user for the ordinary case of an ampersand in an issue title — a visible, everyday bug
      traded for no gain, since a text field does not execute markup. This matches the split the
      earlier fix settled on.

    If Vikunja ever renders titles as rich text, that assumption is wrong and this is the single
    call site to change. `tests/test_sink_escaping.py` asserts both halves so the decision is
    visible rather than inferred.
    """

    def __init__(self, spec: VikunjaTaskSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.title_template)
        validate(spec.description_template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        base = _resolve_url(self.spec, self.secrets)
        token = self.secrets.get(self.spec.token_env, "")
        if not token:
            raise PermanentSinkError(f"{self.name}: {self.spec.token_env} is unset")

        return await self._send(
            client,
            "PUT",
            f"{base}/api/v1/projects/{self.spec.project_id}/tasks",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "title": render(self.spec.title_template, context),
                "description": render_html(self.spec.description_template, context),
            },
        )


class GenericHttpSink(HttpSinkBase):
    """POST/PUT/PATCH a rendered body to any endpoint."""

    def __init__(self, spec: HttpSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        url = _resolve_url(self.spec, self.secrets)
        body = render(self.spec.template, context)

        if self.spec.content_type == "application/json":
            # Catch a template that renders invalid JSON here rather than shipping it and
            # reading the destination's 400 back as an opaque failure.
            try:
                json.loads(body)
            except json.JSONDecodeError as exc:
                raise PermanentSinkError(
                    f"{self.name}: template rendered invalid JSON: {exc}"
                ) from exc

        headers = {"Content-Type": self.spec.content_type, **self.spec.headers}
        if self.spec.token_env:
            token = self.secrets.get(self.spec.token_env, "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        return await self._send(
            client, self.spec.method, url, headers=headers, content=body.encode("utf-8")
        )
