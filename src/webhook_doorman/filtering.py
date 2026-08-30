"""Structural admission control: which events a source is allowed to emit at all.

This is the cheapest and most durable half of content safety, and it is deliberately *not*
statistical. A verified GitHub webhook is a verified delivery of unverified content — the
signature proves GitHub sent it, and says nothing about who wrote `issue.body`. Until now
`SourceConfig` had no way to express that difference. Naming the events a source may emit, and
the payload fields that must or must not hold given values, removes more real risk than any
classifier can, and it does so with an answer that is the same every time.

Three rules are worth stating because each one is a choice:

* **A missing path fails `require` and passes `deny`.** `require` is a guarantee you asked the
  payload to carry; a payload that does not carry it has not provided the guarantee, so it is
  refused. `deny` is a specific thing you are refusing; something absent is not that thing. The
  asymmetry is what makes both usable — a symmetric rule would make one of them useless.
* **Order is `event_types` → `deny` → `require`.** `deny` is checked first so that a payload
  which satisfies `require` *and* matches `deny` is rejected as `deny`, which is the answer an
  operator is looking for when both are configured.
* **A filtered event is stored.** It is not an error and not a rejection — the producer is told
  200, exactly as it is for an event with no sinks. "Understood, deliberately not delivered" is
  a state worth being able to look up later.

Paths resolve into the **decoded payload**, not into the parser's context. `parse_github` does
not expose `author_association`, and a filter has to work under `parser: generic` where there is
no context at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Appended to a value shortened by `max_field_bytes`. Visible on purpose: a silently truncated
#: field reads downstream as a field that was simply short.
TRUNCATION_MARKER = "…[truncated]"

#: Every value `reason` can take, and therefore every value the `events_filtered_total` label
#: can take. Closed, and never the offending *value* — that is producer-controlled and would
#: turn a metric label into unbounded cardinality.
FILTER_REASONS = ("event_type", "deny", "require")


@dataclass(frozen=True)
class FilterVerdict:
    """Whether an event is admissible, and if not, which gate refused it.

    `reason` is one of `FILTER_REASONS` and is safe as a metric label. `detail` names the
    offending *path* — never its value — and is for the log line only.
    """

    admitted: bool
    reason: str | None = None
    detail: str | None = None


ADMITTED = FilterVerdict(admitted=True)


def dig(payload: Any, path: str) -> Any:
    """Resolve a dotted path into a decoded payload. `None` if it does not resolve.

    Defensive in the style of `parsers._dig`: webhook payloads are documented optimistically and
    delivered otherwise, and a filter that raises on a missing key would turn a cosmetic upstream
    change into a rejected delivery.
    """
    current = payload
    for key in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_text(value: Any) -> str:
    """Render a JSON scalar the way the YAML that matches it is written.

    `str(True)` is `"True"`, but the payload said `true` and so does the config. Matching on
    Python's spelling of a JSON value would make `deny: {draft: [true]}` silently never match.
    """
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)


def _matches(value: Any, allowed: list[str]) -> bool:
    """Does the resolved value match any allowed value?

    A list at the path matches if **any** element does. GitHub's `labels` is the case this is
    for: `deny: {issue.labels.name: [...]}` is not expressible, but a rule over a list of
    scalars is, and a list that only ever matched as a whole would be useless.
    """
    if isinstance(value, list):
        return any(_as_text(item) in allowed for item in value)
    return _as_text(value) in allowed


def evaluate(source_filter, event_type: str, payload: Any) -> FilterVerdict:
    """Decide whether one parsed event is admissible under a source's filter.

    Args:
        source_filter: the source's `SourceFilter`. An unset filter admits everything, which is
            what keeps this invisible to every config that does not opt in.
        event_type: the parser's `event_type`, matched against the `event_types` allowlist.
        payload: the **decoded, redacted** body. `require` and `deny` resolve into this.
    """
    allowed_types = source_filter.event_types
    if allowed_types is not None and event_type not in allowed_types:
        return FilterVerdict(False, "event_type", event_type)

    for path, values in source_filter.deny.items():
        resolved = dig(payload, path)
        if resolved is None:
            continue  # Absent is not the thing being refused.
        if _matches(resolved, values):
            return FilterVerdict(False, "deny", path)

    for path, values in source_filter.require.items():
        resolved = dig(payload, path)
        if resolved is None or not _matches(resolved, values):
            # Fail-closed: the payload did not carry the guarantee that was asked for.
            return FilterVerdict(False, "require", path)

    return ADMITTED


def truncate_text(text: str, limit: int) -> str:
    """Shorten `text` to `limit` **bytes** of UTF-8, cutting on a character boundary.

    The limit is a byte budget because that is what bounds storage and what bounds a detector's
    input; the cut is on a character boundary because slicing UTF-8 by byte index produces a
    string that is no longer valid UTF-8. `errors="ignore"` drops the partial trailing sequence,
    which is exactly the boundary cut.

    The marker is added on top of the budget rather than inside it. Reserving room for it would
    make the effective limit depend on the marker's length, which is not a number an operator
    configured.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore") + TRUNCATION_MARKER


def truncate(value: Any, limit: int | None) -> Any:
    """Apply `truncate_text` to every string in a decoded structure. Structure is preserved.

    Applied to the parser's `summary` and `context` at ingest, so the cap is in effect on the
    stored row and a replay delivers the same bytes as the original did. It is deliberately
    **not** applied to `payload`, which is re-derived from the stored body on every read: capping
    one and not the other would make two views of the same event disagree, and capping the body
    itself changes what a replay delivers — the trade `redact_bytes` documents and the one place
    it is worth making.
    """
    if limit is None:
        return value
    if isinstance(value, str):
        return truncate_text(value, limit)
    if isinstance(value, dict):
        return {k: truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [truncate(v, limit) for v in value]
    return value
