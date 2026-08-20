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
"""

from __future__ import annotations

from typing import Any

from jinja2 import ChainableUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from .errors import PermanentSinkError

_env = SandboxedEnvironment(
    autoescape=False,  # output is chat text and JSON bodies, not HTML
    undefined=ChainableUndefined,
    keep_trailing_newline=False,
)


def render(template: str, context: dict[str, Any]) -> str:
    """Render `template` against `context`.

    Raises:
        PermanentSinkError: the template is malformed or its rendering raised. This is a
            configuration mistake, and retrying it five times with backoff only delays the
            moment the operator finds out.
    """
    try:
        return _env.from_string(template).render(**context)
    except TemplateError as exc:
        raise PermanentSinkError(f"template error: {exc}") from exc


def validate(template: str) -> None:
    """Compile a template without rendering it, to fail at startup rather than at delivery.

    Raises:
        PermanentSinkError: the template does not compile.
    """
    try:
        _env.from_string(template)
    except TemplateError as exc:
        raise PermanentSinkError(f"template error: {exc}") from exc
