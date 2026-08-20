"""The seven bundled sinks.

`matrix`, `ntfy` and `vikunja_task` are ported from the listeners this project replaces, minus
their hardcoded endpoint defaults — those were one deployment's topology baked into source, and
carrying them into a public repo is how a homelab's hostnames end up in someone else's traceback.
Every endpoint here comes from config.

`http` is the escape hatch, and it is the reason most destinations do not need siblings. A
generic POST with a rendered body covers any destination that speaks JSON, which is most of
them. One of the receivers this replaced existed solely to shell out to a local reindex command;
as an `http` sink it is a config entry.

`discord`, `slack` and `apprise` are the cases where the escape hatch is a trap rather than a
convenience, and each is here for a specific reason rather than for completeness:

* **Discord and Slack** are reachable through `http` — but only by hand-templating raw JSON,
  and `GenericHttpSink` raises `PermanentSinkError` on a body that does not parse. An issue
  title containing a quote or a newline therefore goes straight to the DLQ unless the operator
  remembered `| tojson`. Building the dict in Python deletes that failure mode. Both then add
  the destination-specific hardening a generic sink has no way to know about.
* **Apprise** is not expressible as an `http` sink at all: two of its response codes need
  semantics `HttpSinkBase` gets wrong, one of them silently.

The `apprise` *library* is deliberately not vendored — see `ARCHITECTURE.md`.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import quote

import httpx

from ..config import (
    AppriseSink,
    DiscordSink,
    HttpSink,
    MatrixSink,
    NtfySink,
    SlackSink,
    VikunjaTaskSink,
)
from ..errors import PermanentSinkError
from ..templating import render, render_html, render_markdown, render_slack, validate
from .base import DeliveryOutcome, Disposition, HttpSinkBase, Verdict


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


# Discord rejects a `content` longer than 2000 characters with a 400, which `_send` classifies
# permanent — so an ordinary long release-notes payload would land in the DLQ rather than being
# delivered slightly short. Truncating with a few characters of headroom is the better trade.
_DISCORD_CONTENT_LIMIT = 2000
_DISCORD_TRUNCATE_AT = 1997


def _truncate(text: str, limit: int, cut: int) -> str:
    """`text` bounded to `limit`, with a visible marker when it was shortened.

    The ellipsis is the point: a silently truncated message reads as a complete one, and an
    operator debugging a half-missing stack trace has no reason to suspect the sink.
    """
    if len(text) <= limit:
        return text
    return text[:cut] + "…"


class DiscordWebhookSink(HttpSinkBase):
    """Post a message to a Discord channel via an incoming webhook.

    **`allowed_mentions` is set on every request and is not configurable.** Discord resolves
    `@everyone` and `@here` out of message `content`, and on any public repo that content is
    attacker-authored — an issue titled `@everyone pwned` mass-pings the server. `{"parse": []}`
    disables all mention resolution. Discord's own webhook documentation recommends exactly this
    for user-generated strings, so it is a vendor position rather than only this project's.

    It is not a config flag on purpose. A flag that defaults safe still lets someone turn it off
    without understanding what it was for, and the blast radius is everyone in the server. An
    operator who wants a real `@here` should open a ticket with a reason.

    Rendered with `render()`, not `render_html()`: Discord content is markdown, and HTML-escaping
    it would put a literal `&amp;` in front of every user for the ordinary case of an ampersand.
    Mention syntax is neutralised by `allowed_mentions` at the API level, which is where it
    belongs — escaping the `@` would corrupt every email address instead.
    """

    def __init__(self, spec: DiscordSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        webhook_url = self.secrets.get(self.spec.webhook_url_env, "").strip()
        if not webhook_url:
            raise PermanentSinkError(f"{self.name}: {self.spec.webhook_url_env} is unset")

        payload: dict[str, Any] = {
            "content": _truncate(
                render(self.spec.template, context),
                _DISCORD_CONTENT_LIMIT,
                _DISCORD_TRUNCATE_AT,
            ),
            "allowed_mentions": {"parse": []},
        }
        if self.spec.username:
            payload["username"] = self.spec.username
        if self.spec.avatar_url:
            payload["avatar_url"] = self.spec.avatar_url

        params = {"thread_id": self.spec.thread_id} if self.spec.thread_id else None
        return await self._send(client, "POST", webhook_url, params=params, json=payload)


class SlackWebhookSink(HttpSinkBase):
    """Post a message to a Slack channel via an incoming webhook.

    Rendered with `render_slack()`, which escapes `&`, `<` and `>` in interpolated values.
    Slack's `mrkdwn` reads `<http://evil|click here>` as a link with arbitrary display text —
    a phishing primitive in a payload field an outsider controls — and `<!channel>` as a
    broadcast. Escaping the angle brackets neutralises both. Like Discord's `allowed_mentions`,
    this is not configurable.

    Note for a future token-based variant, which this is not: Slack's *Web API*
    (`chat.postMessage`) answers HTTP 200 with `{"ok": false, "error": ...}` in the body, which
    the default classification reads as delivered. Incoming webhooks do not behave that way —
    they return a non-2xx and a plain-text reason — so it is not a defect here. Whoever adds
    token posting needs a body-level success check; override `_classify`, which exists for it.
    """

    def __init__(self, spec: SlackSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        webhook_url = self.secrets.get(self.spec.webhook_url_env, "").strip()
        if not webhook_url:
            raise PermanentSinkError(f"{self.name}: {self.spec.webhook_url_env} is unset")

        return await self._send(
            client,
            "POST",
            webhook_url,
            json={"text": render_slack(self.spec.template, context)},
        )


# One entry per member of `AppriseSink.body_format`. Keyed rather than branched so that adding
# a format to the Literal without deciding its escaping raises a KeyError at delivery instead
# of silently inheriting a neighbour's rule.
_APPRISE_BODY_RENDERERS = {
    "text": render,
    "markdown": render_markdown,
    "html": render_html,
}


class AppriseNotifySink(HttpSinkBase):
    """Fan out a notification through an apprise-api instance.

    The substance of this sink is `_classify`, not the request. Two apprise-api response codes
    mean something the default HTTP rule gets wrong:

    * **`204` — no configuration for that key, or no valid URLs to notify.** The default reads
      anything under 400 as delivered, so a typo'd key would swallow every event for as long as
      it took someone to notice that a channel had gone quiet. Nothing is retryable about it —
      the key will still be wrong next time — so it is permanent, and the DLQ row is the point.
    * **`424` — at least one notification failed.** Permanent, and this one is a judgement call
      worth stating. Retrying re-notifies the destinations that already *succeeded*, so five
      attempts produce up to five duplicate messages on the healthy channels while the broken
      one stays broken — noise at exactly the moment an operator is least able to tell which
      channel actually failed. Apprise owns retry for its own downstreams. Doorman's job is to
      make the partial failure visible, and a DLQ row does that without the duplicates.

    Uses the stateful `POST {base}/notify/{key}` form so downstream credentials stay in
    Apprise's store rather than in doorman's config. `Accept: application/json` is set so an
    error response carries a structured `error` field, which is what makes the `response.text`
    excerpt in the `SinkError` message worth reading.

    **Escaping is per `body_format`, and all three modes are decided rather than defaulted.**
    `html` escapes as HTML; `markdown` escapes angle brackets, because apprise-api converts
    Markdown to HTML with an unsanitised Python-Markdown that passes raw tags through; `text`
    is not escaped, because apprise-api runs its own `escape_html` on the text-to-HTML path.
    An audit found `markdown` originally sharing the `text` rule — the format's name made it
    look like a plain-text sibling when its renderer makes it a rich-text one. See
    `render_markdown` for the evidence, and `tests/test_sink_escaping.py` for all three
    asserted, including the negative halves.
    """

    def __init__(self, spec: AppriseSink, secrets: dict[str, str]) -> None:
        self.name = spec.name
        self.spec = spec
        self.secrets = secrets
        validate(spec.template)
        validate(spec.title_template)

    def _classify(self, response: httpx.Response) -> Verdict:
        if response.status_code == 204:
            return Verdict(
                Disposition.PERMANENT,
                "apprise accepted the request but notified nothing — unknown key, "
                "or the key's configuration has no valid URLs",
            )
        if response.status_code == 424:
            return Verdict(
                Disposition.PERMANENT,
                "at least one downstream notification failed; not retried, because a retry "
                "re-notifies the destinations that succeeded",
            )
        return super()._classify(response)

    async def deliver(self, context: dict[str, Any], client: httpx.AsyncClient) -> DeliveryOutcome:
        base = _resolve_url(self.spec, self.secrets)
        key = self.secrets.get(self.spec.key_env, "").strip()
        if not key:
            raise PermanentSinkError(f"{self.name}: {self.spec.key_env} is unset")

        # The body's rendering context is chosen by config, so the escaping has to be too —
        # this is the per-field doctrine applied to a field whose destination is a variable.
        # All three modes are named explicitly rather than defaulting: the first version of
        # this sink wrote `render_html if body_format == "html" else render`, which put
        # `markdown` in the plain-text bucket without checking whether it belonged there. It
        # does not — see `render_markdown`. A dict keyed on every member of the Literal fails
        # loudly if a fourth format is ever added, where a two-way branch would silently
        # inherit whichever side it fell through to.
        #
        # The title is left unescaped in every mode: Apprise maps it onto plain-text slots
        # (an email subject, a push notification title), the same split `VikunjaTaskSink_`
        # settled on for its own title.
        render_body = _APPRISE_BODY_RENDERERS[self.spec.body_format]
        payload: dict[str, Any] = {
            "body": render_body(self.spec.template, context),
            "title": render(self.spec.title_template, context),
            "type": self.spec.notify_type,
            "format": self.spec.body_format,
        }
        if self.spec.tag:
            payload["tag"] = self.spec.tag

        return await self._send(
            client,
            "POST",
            f"{base}/notify/{quote(key, safe='')}",
            headers={"Accept": "application/json"},
            json=payload,
        )
