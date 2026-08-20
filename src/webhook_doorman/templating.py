"""Message templating: Jinja2, sandboxed, text only.

**There is deliberately no scripting engine here.** The comparable projects all took one on —
event-bridge uses RestrictedPython, WebhookX uses JS/wasm, NitroHook uses sandboxed JS — and for
most of them that is a reasonable trade. It is not one for this project. The entire value on
offer is fail-closed verification of untrusted inbound requests; adding an in-process interpreter
that runs operator-authored code over attacker-supplied data undoes more than it adds.

So: `SandboxedEnvironment`, no filesystem loader, no imports, no attribute access to dunders,
and templates that produce text. Recorded as a non-goal in the README so it is a decision rather
than an omission.

Undefined variables render as empty rather than raising. A webhook payload is not a schema, and
a producer that stops sending an optional field should not turn every subsequent delivery into a
retry loop. `ChainableUndefined` extends that through attribute chains, so
`{{ payload.issue.title }}` renders empty instead of exploding when `issue` is absent.

## Three environments, because escaping belongs to the destination

Escaping is a property of where the output is rendered, not of the data. A single global setting
gets one of the cases wrong:

* `render()` — autoescape **off**. Chat messages, push notifications, JSON bodies. HTML-escaping
  these is not hardening, it is corruption: `Fix A & B` arrives in a Matrix room as
  `Fix A &amp; B`, and escaping a JSON body breaks it outright.
* `render_html()` — autoescape **on**. Destinations that render their input as rich text.
* `render_slack()` — Slack's own three-character escape, which is neither of the above.

Slack is the case that proves the split is about destinations rather than about a boolean.
Its `mrkdwn` is not HTML and not plain text: it interprets `<http://evil|click here>` as a
link and `<!channel>` as a broadcast, and it documents an escape set of exactly three
characters — `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`. HTML autoescape is the wrong tool
even though it looks close enough: it also rewrites `"` and `'` to entities, which Slack
renders literally, so every quoted issue title arrives full of `&#34;`.

The split exists because getting it wrong in the other direction was a real finding. Webhook
content is attacker-controlled on any public repo, and the first version of this module rendered
a GitHub issue body into a Vikunja task description — which Vikunja renders as HTML — with
autoescape off. That is stored XSS against whoever opens the task.

It was also a *recurrence*. The service this replaced had the identical defect and fixed it with
`html.escape()` in its **parser**. Porting to templates silently dropped the fix, because a
parser is now shared across sinks and cannot know how any of them render its output. The sink
knows. So the sink chooses, per field.

Autoescape only escapes *interpolated values*. Literal markup in the template is the operator's
own text and passes through, which is what makes `<p>{{ body }}</p>` both useful and safe.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from jinja2 import ChainableUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from .errors import PermanentSinkError


def _build(autoescape: bool, finalize: Callable[[Any], str] | None = None) -> SandboxedEnvironment:
    return SandboxedEnvironment(
        autoescape=autoescape,
        undefined=ChainableUndefined,
        keep_trailing_newline=False,
        finalize=finalize,
    )


# The three characters Slack documents as needing escaping in message text. Order matters:
# `&` must go first, or the ampersands introduced by the other two get double-escaped and
# `<` arrives as `&amp;lt;`.
_SLACK_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"))


def _slack_escape(value: Any) -> str:
    """Escape one interpolated value for Slack `mrkdwn`.

    Used as the Jinja `finalize` hook rather than as an autoescape policy, because Jinja's
    autoescape is hardwired to `markupsafe.escape` and that escapes more than Slack wants.
    `finalize` runs on every `{{ ... }}` expression and is bypassed for literal template text
    (`nodes.TemplateData` in Jinja's code generator), which is the same interpolated-values-only
    guarantee autoescape gives — so `*{{ summary }}*` keeps the operator's bold markers while
    the summary itself cannot open a link or a broadcast.

    Escaping `<` and `>` neutralises `<!channel>` and `<!here>` as a side effect: Slack only
    resolves a broadcast written with literal angle brackets. One rule does both jobs.
    """
    text = str(value)
    for char, replacement in _SLACK_ESCAPES:
        text = text.replace(char, replacement)
    return text


# Plain text: chat, push, JSON bodies. Read the module docstring before changing this.
_text_env = _build(autoescape=False)

# HTML: destinations that render their input as rich text.
_html_env = _build(autoescape=True)

# Slack `mrkdwn`: autoescape off, per-value escaping via `finalize`.
_slack_env = _build(autoescape=False, finalize=_slack_escape)


def _render(env: SandboxedEnvironment, template: str, context: dict[str, Any]) -> str:
    try:
        return env.from_string(template).render(**context)
    except TemplateError as exc:
        raise PermanentSinkError(f"template error: {exc}") from exc


def render(template: str, context: dict[str, Any]) -> str:
    """Render `template` as plain text, without HTML escaping.

    For chat messages, push notifications and JSON bodies. An operator whose destination does
    render HTML can escape a single value with Jinja's `| e` filter; `| tojson` is available for
    JSON bodies and is the correct tool there, since JSON has its own escaping rules.

    Raises:
        PermanentSinkError: the template is malformed or its rendering raised. This is a
            configuration mistake, and retrying it five times with backoff only delays the
            moment the operator finds out.
    """
    return _render(_text_env, template, context)


def render_html(template: str, context: dict[str, Any]) -> str:
    """Render `template` with autoescape on, for a destination that renders rich text.

    Every interpolated value is HTML-escaped; markup written in the template itself is left
    alone, so an operator can still lay out a description.

    Raises:
        PermanentSinkError: the template is malformed or its rendering raised.
    """
    return _render(_html_env, template, context)


def render_slack(template: str, context: dict[str, Any]) -> str:
    """Render `template` for Slack, escaping `&`, `<` and `>` in interpolated values.

    Not `render_html` with a different name. Slack's `mrkdwn` is its own rendering context: it
    reads `<url|label>` as a link and `<!channel>` as a broadcast, so the three characters have
    to go — but it renders `"` and `'` literally, so HTML escaping would corrupt every quoted
    title for no gain. See the module docstring.

    Only interpolated values are escaped; markup written in the template itself is the
    operator's own text and passes through, so `*{{ source }}*` still renders bold.

    Raises:
        PermanentSinkError: the template is malformed or its rendering raised.
    """
    return _render(_slack_env, template, context)


def validate(template: str) -> None:
    """Compile a template without rendering it, to fail at startup rather than at delivery.

    Compilation is independent of both autoescape and `finalize` — neither can turn a
    well-formed template into a syntax error — so one check against `_text_env` covers all
    three environments, including `_slack_env`.

    Raises:
        PermanentSinkError: the template does not compile.
    """
    try:
        _text_env.from_string(template)
    except TemplateError as exc:
        raise PermanentSinkError(f"template error: {exc}") from exc
