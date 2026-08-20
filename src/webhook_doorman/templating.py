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

## Two environments, because escaping belongs to the destination

Escaping is a property of where the output is rendered, not of the data. A single global setting
gets one of the two cases wrong:

* `render()` — autoescape **off**. Chat messages, push notifications, JSON bodies. HTML-escaping
  these is not hardening, it is corruption: `Fix A & B` arrives in a Matrix room as
  `Fix A &amp; B`, and escaping a JSON body breaks it outright.
* `render_html()` — autoescape **on**. Destinations that render their input as rich text.

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

from typing import Any

from jinja2 import ChainableUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from .errors import PermanentSinkError


def _build(autoescape: bool) -> SandboxedEnvironment:
    return SandboxedEnvironment(
        autoescape=autoescape,
        undefined=ChainableUndefined,
        keep_trailing_newline=False,
    )


# Plain text: chat, push, JSON bodies. Read the module docstring before changing this.
_text_env = _build(autoescape=False)

# HTML: destinations that render their input as rich text.
_html_env = _build(autoescape=True)


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


def validate(template: str) -> None:
    """Compile a template without rendering it, to fail at startup rather than at delivery.

    Compilation is independent of autoescape, so one check covers both environments.

    Raises:
        PermanentSinkError: the template does not compile.
    """
    try:
        _text_env.from_string(template)
    except TemplateError as exc:
        raise PermanentSinkError(f"template error: {exc}") from exc
