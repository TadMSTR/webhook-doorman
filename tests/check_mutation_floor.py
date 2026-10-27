#!/usr/bin/env python3
"""Fail if the mutation score of the security modules got worse.

Run after `mutmut run` (configured in pyproject.toml `[tool.mutmut]`), from the repo root:

    mutmut run --max-children 4 && python tests/check_mutation_floor.py

Line coverage says a line ran. A surviving mutant says a test ran it and would not have noticed
it changing, which for `verification.py` is the difference between a constant-time comparison and
`!=` (#759). So the gate is on survivors, per module:

* **MAX_SURVIVED** is a ceiling, measured, not chosen. Most survivors are equivalent mutants (a
  codec name in upper case, `None` for `False` in an always-falsy result, a reworded log reason)
  and are listed in the PR that set the numbers. A new survivor means a new branch no test pins.
  Lower a ceiling when you kill one; never raise it to make a build pass.
* **MIN_MUTANTS** is the vacuity guard. A config that stopped mutating a module would report
  zero survivors, which is the same output as a perfect score.
* Anything not `killed` or `survived` (not checked, timeout, suspicious, segfault) fails: the
  run did not finish, so its numbers prove nothing.

Not named test_*.py: pytest must not collect it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter

#: Measured 2026-10-27 on the 0.7.0 branch (mutmut 3.8.0): verification 284 mutants / 83
#: survived, secrets 112 / 11, filtering 118 / 5. Every remaining survivor was read and is
#: equivalent; the classes are listed in the module docstring. The real ones that run found
#: (Basic auth `or`/`and` and `partition`, `deny` `continue`/`break`, `resolve` loop exits,
#: the metrics-token length boundary) have tests now and are not in these numbers.
#:
#: verification 83 -> 85 after the 0.7.0 audit (CR-08: `secure_compare` refuses empty input).
#: Both new survivors were read and are equivalent BECAUSE of that guard, not test gaps:
#: `secure_compare`'s own `or` -> `and` (with one side empty, compare_digest is False anyway),
#: and `verify_basic`'s `if not user or not password` -> `and` (an empty half can no longer
#: match an empty presented half, since the choke point refuses it). Raised with that reason;
#: never raise a ceiling without reading the survivors.
MAX_SURVIVED = {
    "webhook_doorman.verification": 85,
    "webhook_doorman.secrets": 11,
    "webhook_doorman.filtering": 5,
}
#: About 10% under the measured counts, so ordinary edits do not trip it and losing a module's
#: mutants does.
MIN_MUTANTS = {
    "webhook_doorman.verification": 250,
    "webhook_doorman.secrets": 100,
    "webhook_doorman.filtering": 105,
}

LINE = re.compile(r"^\s*(?P<module>[\w.]+)\.x\w*?__mutmut_\d+: (?P<status>[\w ]+)$")


def main() -> int:
    out = subprocess.run(
        ["mutmut", "results", "--all", "true"], capture_output=True, text=True, check=True
    ).stdout
    counts: dict[str, Counter] = {m: Counter() for m in MAX_SURVIVED}
    unknown: list[str] = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        module, status = m["module"], m["status"].strip()
        if module not in counts:
            unknown.append(f"unexpected module mutated: {module}")
            continue
        counts[module][status] += 1

    failures = list(unknown)
    for module, c in counts.items():
        total = sum(c.values())
        other = {k: v for k, v in c.items() if k not in ("killed", "survived")}
        summary = f"{module}: {total} mutants, {c['killed']} killed, {c['survived']} survived"
        print(f"{summary} {other}" if other else summary)
        if total < MIN_MUTANTS[module]:
            failures.append(f"{module}: only {total} mutants (floor {MIN_MUTANTS[module]})")
        if other:
            failures.append(f"{module}: unfinished mutants {other}")
        if c["survived"] > MAX_SURVIVED[module]:
            failures.append(
                f"{module}: {c['survived']} survived, ceiling {MAX_SURVIVED[module]}. "
                "Run `mutmut results` and `mutmut show <name>` for the new survivor."
            )
    for f in failures:
        print(f"::error::{f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
