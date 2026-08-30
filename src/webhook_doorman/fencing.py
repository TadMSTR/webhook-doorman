"""Mark attacker-authored fields in rendered output, for destinations that feed an LLM.

A verified webhook is a verified delivery of *unverified content*. GitHub's signature proves
GitHub sent the request; it says nothing about who wrote `issue.body`. When the destination is
a chat room a human reads, that distinction is handled by the human. When the destination is an
agent, nothing handles it unless the rendered text says which parts were authored by a stranger.

So a fenced field arrives as:

    <untrusted source="github" field="body">
    ...content...
    </untrusted>

## Why this builds a context dict rather than using a Jinja `finalize` hook

Both alternatives were checked against the code rather than assumed, and both are wrong:

* **`finalize` sees values, not names.** `template_context()` is a flat namespace where
  `source`, `event_type` and `delivery_id` sit alongside `summary`, `payload` and everything a
  parser merged in. A `finalize` hook would fence `{{ source }}` too, which is our own field and
  the one an agent most needs to trust.
* **A marker type does not survive the round trip.** `class Untrusted(str)` is destroyed by
  `redaction._walk`, which calls `str.replace` and gets a plain `str` back, and again by the
  `context_json` round trip, since a replayed event is rebuilt from the stored row. The fences
  would be lost on the replay path *only* — a bug that is invisible until the day someone
  replays an event, which is the day they least want a surprise.

Instead the parser declares which context keys it filled from attacker-authored data, that list
is persisted alongside the event, and the fence is applied when the context is built.

## The tag is the load-bearing part

Content that can write `</untrusted>` can end the fence early and continue as trusted text, so
any closing tag in the content is removed before wrapping. The match is deliberately looser than
the tag this module emits - `</ untrusted >` and `</UNTRUSTED>` are removed too, because the
reader being protected is a language model, not a strict parser, and it will treat those as a
close.

**Forged *opening* tags are removed as well.** They cannot produce an escape on their own: the
real closing tag is appended once, after all field content, so anything a forged open introduces
stays inside the true span whatever `source` attribute it claims. What they can do is unbalance
the structure, and the fence's whole job is to be an unambiguous signal about which words came
from a stranger - a nested `<untrusted source="trusted-thing">` muddies exactly the thing the
delimiter exists to say. Stripping them costs nothing: tag syntax bearing this module's own
delimiter name has no legitimate meaning inside a webhook payload.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .sanitize import sanitize

#: Matches any plausible spelling of the fence tag - opening or closing, with or without
#: attributes. Case-insensitive and whitespace-tolerant because the consumer is an LLM: a fence
#: that only stops an exact-match forgery is not one.
#:
#: The lookahead is what keeps this from over-reaching. `untrusted` must be followed by
#: whitespace or `>`, so a payload containing `<untrusted-data>` is left alone while
#: `<untrusted source="...">` is not.
_FENCE_TAG = re.compile(r"</?\s*untrusted(?=[\s>])[^>]*>", re.IGNORECASE)


def _attribute(value: str) -> str:
    """Quote a tag attribute. Both values are ours, but a malformed tag is still a broken fence."""
    return '"' + value.replace("\\", "").replace('"', "").replace("\n", " ") + '"'


def fence_text(content: str, *, source: str, field: str) -> str:
    """Wrap one field's content in a fence it cannot escape.

    The content is sanitised first. Fencing a field is a promise about where its boundaries are,
    and invisible characters inside it would let the content say one thing to a reviewer reading
    the log and another to the model reading the message.
    """
    cleaned, _ = sanitize(content)
    cleaned = _FENCE_TAG.sub("", cleaned)
    return (
        f"<untrusted source={_attribute(source)} field={_attribute(field)}>\n"
        f"{cleaned}\n"
        f"</untrusted>"
    )


def _as_text(value: Any) -> str:
    """Render a value for fencing.

    A non-string field is serialised as JSON. `parse_generic` marks the whole `payload` as
    untrusted, and a fence can only be placed around text - see `fence_context` for what that
    costs a template.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def fence_context(context: dict[str, Any], *, source: str, fields: list[str]) -> dict[str, Any]:
    """Return `context` with every key in `fields` replaced by its fenced text.

    Keys not in `fields` are returned untouched, which is the point: `source`, `event_type`,
    `delivery_id`, `event_id` and `received_at` are ours and stay outside the fence so an agent
    can rely on them.

    **A fenced field becomes a string.** For `payload` that means `{{ payload.issue.title }}`
    renders empty on an `agent_readable` sink, because the fence is placed around the payload as
    a whole and there is no way to wrap a dict while keeping attribute access. That is a
    deliberate, documented cost of opting a sink in: use a parser's named context fields, which
    are fenced individually, or leave the sink `agent_readable: false`. A missing key in
    `fields` is skipped rather than invented, so a parser naming a field it did not fill costs
    nothing.
    """
    fenced = dict(context)
    for field in fields:
        if field not in fenced:
            continue
        fenced[field] = fence_text(_as_text(fenced[field]), source=source, field=field)
    return fenced
