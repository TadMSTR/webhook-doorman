"""Remove characters that have no legitimate place in a webhook payload.

**This is not a heuristic.** It is the same class of rule as the header redaction in
`redaction.py`: a closed, named set of things that are removed because they are never wanted,
not because a model scored them. Nothing here tries to decide whether text is an attack. That
distinction is the whole reason this module is separate from `detect.py` — one of them has a
correct answer and the other has a confidence, and mixing them would let the confident one
inherit the other's authority.

What is removed, and why each set is here:

* **Unicode tag block (U+E0000-U+E007F)** — an invisible mirror of ASCII. A tag-encoded
  sentence renders as nothing at all in every terminal, editor and chat client, and arrives at
  a language model as text. It is the canonical instruction-smuggling channel and it has no
  other use.
* **Bidi overrides (U+202A-U+202E, U+2066-U+2069)** — reorder rendered text independently of
  its logical order, so what a human reviews and what a machine reads can be made to differ.
* **Zero-width (U+200B-U+200D, U+FEFF)** — invisible, and enough of them carry a payload or
  break up a string that a downstream filter is matching on.
* **C0/C1 controls except tab, newline and carriage return** — the three kept are the ones that
  legitimately appear in a webhook body. The rest are terminal control, and an event log is
  read in a terminal.

Then **NFKC**, which folds compatibility forms onto their canonical equivalents: the fullwidth
less-than sign U+FF1C becomes an ordinary `<`, and the various lookalike spellings of a keyword
collapse onto one. Normalising *before* stripping is deliberate - a normaliser that can emit new
characters must run ahead of the filter that removes them, or the filter's guarantee only holds
for its input. `test_nfkc_never_produces_a_stripped_character` checks that ordering against the
whole of Unicode rather than assuming it.

`sanitize` returns the classes it acted on, never the text it removed. The classes are a closed
vocabulary and are safe as a metric label; the removed text is producer-controlled and is not.
"""

from __future__ import annotations

import unicodedata

#: Every class `sanitize` can report, and therefore every value the `content_sanitized_total`
#: `class` label can take. Closed — see the module docstring on why the removed text is not here.
SANITIZE_CLASSES = ("tag", "bidi", "zero_width", "control", "normalized")

#: Control characters that stay. A webhook body legitimately contains all three.
_KEPT_CONTROLS = frozenset("\t\n\r")


def _class_of(char: str) -> str | None:
    """Which removal class this character belongs to, or `None` to keep it."""
    point = ord(char)
    if 0xE0000 <= point <= 0xE007F:
        return "tag"
    if 0x202A <= point <= 0x202E or 0x2066 <= point <= 0x2069:
        return "bidi"
    if point in (0x200B, 0x200C, 0x200D, 0xFEFF):
        return "zero_width"
    if (point < 0x20 and char not in _KEPT_CONTROLS) or point == 0x7F or 0x80 <= point <= 0x9F:
        return "control"
    return None


def sanitize(text: str) -> tuple[str, frozenset[str]]:
    """Normalise and strip `text`.

    Returns:
        `(cleaned, classes)` where `classes` names what was acted on — a subset of
        `SANITIZE_CLASSES`, empty when the text was already clean. Deterministic and
        idempotent: sanitising the output again returns it unchanged with an empty set.
    """
    normalised = unicodedata.normalize("NFKC", text)
    classes: set[str] = set()
    if normalised != text:
        classes.add("normalized")

    kept: list[str] = []
    for char in normalised:
        found = _class_of(char)
        if found is None:
            kept.append(char)
        else:
            classes.add(found)
    return "".join(kept), frozenset(classes)


def sanitize_structure(value, classes: set[str]) -> object:
    """Sanitise every string in a decoded structure, accumulating the classes acted on.

    Structure is preserved; only string leaves change. `classes` is mutated rather than
    returned so one pass over a nested context yields one set to count from.
    """
    if isinstance(value, str):
        cleaned, found = sanitize(value)
        classes.update(found)
        return cleaned
    if isinstance(value, dict):
        return {k: sanitize_structure(v, classes) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_structure(v, classes) for v in value]
    return value
