"""Prompt-injection detection: an interface, and one backend that cannot be unavailable.

**Detection is not verification, and this module must never be wired as though it were.** The
premise of this project is that "verification was skipped" is not a reachable outcome. That
works because HMAC has a correct answer. A prompt-injection classifier does not - it has a
confidence. Put one in the admit/refuse path and there are only two ways out, and both are the
shape this project exists to remove: refuse on a low-confidence hit and legitimate events are
dropped, or admit on classifier error and you have written `return True  # skip the check` with
extra steps.

So a verdict here annotates or quarantines. It never rejects at the door, and `on_error: drop`
is refused at config load rather than being offered and warned about.

## Three outcomes, not two

`score()` returns `None` for "could not evaluate" - the null-return degrade shape borrowed from
`searxng-mcp`'s `getValkey()`. `None` is never conflated with a clean verdict, and the metric
carries `verdict="unavailable"` as a first-class value alongside `clean` and `flagged`. That
distinction is the entire point of the contract: a detector that has been down for an hour
reports `unavailable` climbing while `flagged` sits at zero. Fold the two together and the same
outage reads as "everything is clean", which is the most dangerous sentence a security control
can say.

## Why only a heuristic backend ships here

The reference open-source classifier for this task is a 184M-parameter DeBERTa model, roughly
250MB before torch. "One container, one volume" is a load-bearing claim in this project's README,
and bundling that would multiply the image about tenfold. It also would not buy certainty:
arXiv 2510.01529 documents controlled-release bypasses against exactly this class of guard. The
score is telemetry, not a boundary.

HTTP and Ollama backends arrive in a later build, purely additively behind `Detector`. Shipping
the interface first with a backend that *cannot* fail is deliberate: it means the degradation
contract above is exercised by something predictable before it is exercised by something that
can genuinely go away.

## The rules return names, never matched text

A rule name is a closed vocabulary and is safe in a log line, a metric and an admin API
response. The text that matched is payload content - it is the attacker's words, and copying
them into telemetry moves the injection from the event log to the dashboard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class DetectionResult:
    """One backend's verdict on one event's untrusted text.

    `score` is 0.0-1.0. `rules` names what matched and is empty for a heuristic clean. `backend`
    and `model_version` exist so a stored verdict stays interpretable after the backend behind it
    has changed - a score of 0.9 means nothing without knowing what produced it.
    """

    score: float
    backend: str
    rules: list[str] = field(default_factory=list)
    model_version: str | None = None

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "backend": self.backend,
            "rules": list(self.rules),
            "model_version": self.model_version,
        }


@runtime_checkable
class Detector(Protocol):
    """Score one piece of untrusted text."""

    name: str

    async def score(self, text: str) -> DetectionResult | None:
        """Return a verdict, or `None` if this backend could not evaluate the text.

        `None` means "no answer", not "clean". An implementation must return it rather than
        returning a zero score on failure, and it must not raise: the caller's job is to record
        an unavailable verdict, not to absorb an exception from every backend separately.
        """
        ...


#: Scored patterns. Weights are additive and the total is clamped at 1.0, so a single strong
#: signal reaches the default threshold of 0.8 on its own while two weak ones have to agree.
#:
#: The set is small on purpose. False positives are the expected failure mode - a security repo's
#: issue tracker carries "ignore all previous instructions" as ordinary content - which is why
#: `annotate` is the default disposition and why this table is easier to read than to tune.
#:
#: **Every quantifier here is bounded, and none is nested.** These patterns run over
#: attacker-controlled text on the request path, so a rule that backtracks catastrophically is a
#: denial of service rather than a slow rule. Measured worst case across all eight on a full
#: 1 MiB body is ~70ms, scaling linearly; `test_no_rule_backtracks_catastrophically` pins the
#: shape. A new rule that needs an unbounded or nested quantifier needs a different design.
#: `filter.max_field_bytes` is the operator-facing control on this input size.
_RULES: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    (
        "imperative_override",
        0.8,
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|earlier|above|all)\b[^.\n]{0,40}?"
            r"\b(?:instruction|instructions|prompt|prompts|rules?|context)\b",
            re.IGNORECASE,
        ),
    ),
    (
        # The delimiter this project's own fencing uses. Content trying to write it is not
        # ambiguous about intent, and it is the highest-signal rule here.
        "fence_forgery",
        0.8,
        # Deliberately the same shape as `fencing._FENCE_TAG`, including attributes. Matching
        # only the bare `<untrusted>` would miss the realistic forgery, which mimics the real
        # tag and therefore carries a `source` attribute. Stripping and scoring are separate
        # jobs - `fencing` neutralises it, this records that someone tried.
        re.compile(r"</?\s*untrusted(?=[\s>])[^>]*>", re.IGNORECASE),
    ),
    (
        "role_marker",
        0.7,
        re.compile(
            r"(?:<\|im_(?:start|end)\|>|<\|(?:system|user|assistant)\|>|\[/?INST\]|<</?SYS>>"
            r"|^\s*(?:system|assistant)\s*:)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "tool_call_syntax",
        0.6,
        re.compile(
            r"(?:</?(?:function_calls|invoke|tool_call|tool_use)\b|```\s*(?:tool_call|function))",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_disclosure",
        0.5,
        re.compile(
            r"\b(?:repeat|reveal|print|show|output|disclose)\b[^.\n]{0,30}?"
            r"\b(?:system\s+prompt|your\s+(?:instructions|prompt|rules)|initial\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "new_persona",
        0.4,
        re.compile(
            r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(?:a|an|the)\b"
            r"|pretend\s+(?:to\s+be|you\s+are))",
            re.IGNORECASE,
        ),
    ),
    (
        # Weak alone - an image in an issue body is ordinary - but markdown image exfiltration
        # works precisely because it is ordinary, so it earns a small weight that pushes a
        # borderline event over when something else agrees.
        "exfil_markdown_image",
        0.2,
        re.compile(r"!\[[^\]]*\]\(\s*https?://", re.IGNORECASE),
    ),
    (
        "base64_blob",
        0.3,
        re.compile(r"[A-Za-z0-9+/]{256,}={0,2}"),
    ),
)

#: Every rule name the heuristic backend can report. Closed, and asserted against `_RULES` by
#: test rather than restated by hand.
HEURISTIC_RULES = tuple(name for name, _, _ in _RULES)


class HeuristicDetector:
    """Dependency-free scored pattern matching. Never returns `None` - it cannot fail.

    That is a feature rather than an oversight: it means the `unavailable` branch of the
    contract is exercised by tests and by a later out-of-process backend, not by this one
    intermittently.
    """

    name = "heuristic"

    #: Bumped when `_RULES` changes in a way that moves scores, so a verdict stored last month
    #: stays interpretable.
    version = "1"

    async def score(self, text: str) -> DetectionResult:
        total = 0.0
        matched: list[str] = []
        for rule_name, weight, pattern in _RULES:
            if pattern.search(text):
                matched.append(rule_name)
                total += weight
        return DetectionResult(
            score=min(1.0, round(total, 3)),
            backend=self.name,
            rules=matched,
            model_version=self.version,
        )


def build_detector(backend: str) -> Detector | None:
    """Instantiate the configured backend. `None` for `backend: none`, which is the default.

    A name with no implementation is a startup failure rather than a silent no-op, for the same
    reason `sinks.build_sink` raises: a content check the operator believes is running and which
    is not is worse than one they know is off.
    """
    if backend == "none":
        return None
    if backend == "heuristic":
        return HeuristicDetector()
    raise ValueError(f"unknown detector backend {backend!r}")
