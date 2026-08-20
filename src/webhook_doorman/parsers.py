"""Parsers turn a vendor payload into the variables a sink template renders.

A parser is deliberately small and deliberately dumb: it names the event, writes a one-line
summary, and exposes whatever extra fields are worth templating against. It does not decide
where anything goes — routing is config, and no sink knows its source.

`generic` is the default and works for any producer: it hands the whole decoded payload to the
template and lets the operator write the message. A named parser only earns its place when it
saves every adopter from re-deriving the same field paths, as GitHub's nested issue/PR shapes do.

Every field access is defensive. Webhook payloads are documented optimistically and delivered
otherwise — a parser that raises on a missing key turns a cosmetic upstream change into a
rejected delivery.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import ConfigError


@dataclass
class ParsedEvent:
    """The template context for one event.

    Attributes:
        event_type: a stable name for what happened, e.g. `issues.opened`. Used in logs and
            available to templates.
        summary: a single line suitable as a chat message or task title.
        actionable: False means "understood, but nothing to deliver" — the router acknowledges
            with 200 and dispatches to no sink. An unhandled event is not an error; answering it
            with a 4xx makes well-behaved producers retry harder.
        context: extra variables merged into the template namespace.
    """

    event_type: str
    summary: str
    actionable: bool = True
    context: dict[str, Any] = field(default_factory=dict)


Parser = Callable[[Any, Mapping[str, str]], ParsedEvent]


def _decode(body: bytes) -> Any:
    """Decode a JSON body, or return None. Never raises — a non-JSON body is still an event."""
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def parse_generic(payload: Any, headers: Mapping[str, str]) -> ParsedEvent:
    """Default parser: expose the payload as-is and let the template do the work."""
    event_type = headers.get("x-event-type") or headers.get("x-github-event") or "webhook"
    if isinstance(payload, dict):
        for key in ("event", "event_name", "event_type", "type", "action"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                event_type = value
                break
    return ParsedEvent(event_type=event_type, summary=f"{event_type} event received")


def parse_github(payload: Any, headers: Mapping[str, str]) -> ParsedEvent:
    """Parse a GitHub webhook.

    Only a newly *opened* issue or pull request is actionable — everything else is acknowledged
    and dropped. Ported from `vikunja-webhook-listener`, including its escaping rule below.
    """
    gh_event = headers.get("x-github-event", "")
    if not isinstance(payload, dict):
        return ParsedEvent(gh_event or "github", "unparseable GitHub payload", actionable=False)

    action = payload.get("action", "")
    event_type = f"{gh_event}.{action}" if action else (gh_event or "github")

    if gh_event == "ping":
        return ParsedEvent("ping", "GitHub webhook ping", actionable=False)

    resource = payload.get("issue") if gh_event == "issues" else payload.get("pull_request")
    if (
        gh_event not in {"issues", "pull_request"}
        or action != "opened"
        or not isinstance(resource, dict)
    ):
        return ParsedEvent(event_type, f"GitHub {event_type}", actionable=False)

    repo = _dig(payload, "repository", "full_name") or "unknown/unknown"
    number = resource.get("number", "?")
    title = resource.get("title") or "(untitled)"
    url = resource.get("html_url") or ""
    author = _dig(resource, "user", "login") or "unknown"
    body = (resource.get("body") or "").strip()
    kind = "PR" if gh_event == "pull_request" else "issue"

    return ParsedEvent(
        event_type=event_type,
        summary=f"[{repo}#{number}] {title}",
        context={
            "repo": repo,
            "number": number,
            "title": title,
            "url": url,
            "author": author,
            "body": body,
            "kind": kind,
        },
    )


def parse_vikunja(payload: Any, headers: Mapping[str, str]) -> ParsedEvent:
    """Parse a Vikunja webhook.

    Two event names are easy to get wrong, and both were verified against Vikunja's docs rather
    than assumed: there is **no** `task.done` event — completion arrives as `task.updated` with
    the task's `done` field true — and reminders fire as `task.reminder.fired`, a *user* webhook
    event, not `task.reminder`.
    """
    if not isinstance(payload, dict):
        return ParsedEvent("vikunja", "unparseable Vikunja payload", actionable=False)

    event_name = payload.get("event_name") or "vikunja"
    data = payload.get("data")
    data = data if isinstance(data, dict) else {}
    task = data.get("task")
    task = task if isinstance(task, dict) else {}

    title = task.get("title") or "(untitled)"
    task_id = task.get("id")

    if event_name == "task.updated" and task.get("done") is True:
        summary = f"Task completed: {title}"
        event_name = "task.done"
    elif event_name == "task.comment.created":
        author = _dig(data, "comment", "author", "username") or "someone"
        summary = f"Comment by {author} on: {title}"
    else:
        summary = f"{event_name}: {title}"

    return ParsedEvent(
        event_type=event_name,
        summary=summary,
        context={"title": title, "task_id": task_id, "done": bool(task.get("done"))},
    )


def parse_grafana(payload: Any, headers: Mapping[str, str]) -> ParsedEvent:
    """Parse a Grafana alerting webhook (Alertmanager-shaped).

    Every field here is optional in practice, whatever the docs imply — the payload varies with
    the alert rule, the notification template and the Grafana version. Hence the defensive
    chains: a missing `alerts` array produces a thin summary, not a rejected delivery.

    Note Grafana does not sign its payloads at all. Absorbing that with a `bearer` or `basic`
    verify block, rather than a fourth bespoke endpoint, is the case this project's source
    abstraction exists to handle.
    """
    if not isinstance(payload, dict):
        return ParsedEvent("grafana", "unparseable Grafana payload", actionable=False)

    status = payload.get("status") or "unknown"
    alerts = payload.get("alerts")
    alerts = alerts if isinstance(alerts, list) else []
    firing = sum(1 for a in alerts if isinstance(a, dict) and a.get("status") == "firing")

    title = (
        payload.get("title")
        or _dig(payload, "commonLabels", "alertname")
        or (_dig(alerts[0], "labels", "alertname") if alerts else None)
        or "Grafana alert"
    )
    message = payload.get("message") or _dig(payload, "commonAnnotations", "summary") or ""

    marker = {"firing": "[FIRING]", "resolved": "[RESOLVED]"}.get(status, f"[{status.upper()}]")
    summary = f"{marker} {title}"
    if message:
        summary = f"{summary} — {message}"

    return ParsedEvent(
        event_type=f"grafana.{status}",
        summary=summary,
        context={
            "status": status,
            "title": title,
            "message": message,
            "alert_count": len(alerts),
            "firing_count": firing,
            "external_url": payload.get("externalURL") or "",
        },
    )


def _dig(mapping: Any, *keys: str) -> Any:
    """Walk nested dicts, returning None the moment the path stops being a dict."""
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


_PARSERS: dict[str, Parser] = {
    "generic": parse_generic,
    "github": parse_github,
    "vikunja": parse_vikunja,
    "grafana": parse_grafana,
}


def get_parser(name: str) -> Parser:
    """Look up a parser by the name a source's `parser:` field carries.

    Raises:
        ConfigError: no such parser. Raised at startup during registry construction, never at
            request time.
    """
    try:
        return _PARSERS[name]
    except KeyError:
        known = ", ".join(sorted(_PARSERS))
        raise ConfigError(f"unknown parser {name!r} (available: {known})") from None


def register_parser(name: str, parser: Parser) -> None:
    """Add a parser. Exists for tests and for downstream code embedding this package."""
    _PARSERS[name] = parser


def parse(name: str, body: bytes, headers: Mapping[str, str]) -> ParsedEvent:
    """Decode `body` and run the named parser over it."""
    return get_parser(name)(_decode(body), headers)
