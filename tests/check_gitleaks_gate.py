#!/usr/bin/env python3
"""Prove the secret-scanning gate can fail before believing it passes.

"no leaks found" is what a working gate reports on a clean tree and what a misconfigured one
reports on any tree. The green tick alone cannot tell them apart. So every probe here plants a
credential into a THROWAWAY COPY of the repo, commits it, deletes it again, and requires
gitleaks to find it in history by the specific rule meant to catch it. Only after that is the
real history's clean result worth reading.

The probes, in order:

  github-pat       a default gitleaks rule. Proves the scanner reads history at all.
  matrix-room-id   this repo's own topology rule (.gitleaks.toml). A custom rule with a typo
  private-ipv4     in its regex fails silently: it compiles, never matches, and the scan is
                   green. Asserting the rule ID, not just "something fired", is what catches it.
  allowlist-scope  an UNMARKED credential in a file named like a real test file. The allowlist
                   excuses fixture VALUES. gitleaks ORs `paths` with `regexes`, so a path entry
                   covering tests/ would excuse anything pasted there. This must still fire.
  real history     the repository itself, with the same command CI runs.

Copied, never planted in place: a committed secret stays in history after `git rm`, so planting
into the real repo would poison it for good.

Not named test_*.py, so pytest does not collect it. Not skippable: a missing gitleaks is a
failure, because a skip reads the same as a pass. Run it with:

    python tests/check_gitleaks_gate.py

Ported from homelab-ops-mcp (which took it from loki-mcp). The allowlist-scope probe comes from
scribe's version of this file.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The version secret-scan.yml installs. A different binary means a different ruleset: forge's
#: Debian gitleaks has no entropy floor on github-pat, so a probe can pass there and fail in CI.
GITLEAKS_PINNED = "8.30.1"

#: A distinct exit code for "found something". gitleaks exits 1 for an operational error AND,
#: by default, for a finding, so "any non-zero" would accept a scan that broke before reading
#: anything.
LEAK_EXIT = 42

# Every planted value is assembled at runtime, so THIS FILE contains nothing credential-shaped
# and the real-history scan stays meaningful. Each body has real entropy: gitleaks 8.28+ applies
# an entropy floor to github-pat, and a repeated-character body is not reported (measured
# 2026-09-20, loki-mcp). None of them may match an allowlist regex in .gitleaks.toml, or the
# probe would pass for the wrong reason: no `example.*`, no documentation IP range.
_PAT = "ghp_" + "x9Kq2mVb7TzR4nJ8pLw3sYd6HgF5cQa1BeN0"
_ROOM = "!" + "QwfPzGkLmXcVbNtYr" + ":chat." + "zqvkr" + ".net"
_IP = "10." + "44.7.12"

PROBES: list[tuple[str, str, str, str]] = [
    # (label, path in the copy, file content, rule id that must fire)
    ("github-pat", "planted_secret.py", f'GITHUB_TOKEN = "{_PAT}"\n', "github-pat"),
    ("matrix-room-id", "planted_room.yml", f'room_id: "{_ROOM}"\n', "matrix-room-id"),
    ("private-ipv4", "planted_host.yml", f"url: http://{_IP}:8080/\n", "private-ipv4-literal"),
    (
        "allowlist-scope",
        "tests/test_verification.py",
        f'GITHUB_TOKEN = "{_PAT}"\n',
        "github-pat",
    ),
]

SKIP = shutil.ignore_patterns(
    ".git",
    ".venv",
    ".venv-*",
    "__pycache__",
    "*.egg-info",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    "dist",
    "build",
    "*.db",
)


def run_gitleaks(source: Path) -> tuple[int, set[str], list[str]]:
    """Return `(exit code, rule IDs, finding locations)`. The report goes outside `source`.

    A location is `rule file:line commit`, never the match: `--redact` keeps the value out of
    the report, and printing a location is what lets someone fix a history finding at all.
    """
    with tempfile.TemporaryDirectory() as rd:
        report = Path(rd) / "report.json"
        code = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                str(source),
                "--redact",
                "--no-banner",
                "--exit-code",
                str(LEAK_EXIT),
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        findings: list[dict] = []
        if report.exists():
            # Unparseable means "no rule IDs recovered". The exit code is still returned.
            with contextlib.suppress(ValueError):
                findings = json.loads(report.read_text() or "[]")
        rules = {f.get("RuleID", "") for f in findings}
        where = [
            f"{f.get('RuleID')} {f.get('File')}:{f.get('StartLine')} {str(f.get('Commit'))[:12]}"
            for f in findings
        ]
        return code, rules, where


def probe(label: str, rel: str, content: str, rule: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(REPO, work, ignore=SKIP)
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        existed = target.exists()
        original = target.read_bytes() if existed else b""
        # Appended to an existing file rather than replacing it, so the allowlist-scope probe
        # sits among real fixture values, the way a pasted credential would.
        target.write_bytes(original + content.encode())

        git = ["git", "-C", str(work), "-c", "user.email=gate@test", "-c", "user.name=gate"]
        subprocess.run(["git", "init", "-q", str(work)], check=True, capture_output=True)
        subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-qm", "planted"], check=True, capture_output=True)
        # Then take it out again. The secret now exists only in history, so a detection proves
        # the scan reads history, which is what the scheduled full-history run relies on.
        if existed:
            target.write_bytes(original)
            subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
        else:
            subprocess.run([*git, "rm", "-q", rel], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-qm", "removed"], check=True, capture_output=True)
        if content.encode() in (target.read_bytes() if target.exists() else b""):
            print(f"FAIL  {label}: the planted value is still in the working tree")
            return False

        code, rules, _ = run_gitleaks(work)
        if code != LEAK_EXIT:
            what = "NOT detected" if code == 0 else f"a scanner ERROR (exit {code})"
            print(f"FAIL  {label}: planted value was {what}, expected exit {LEAK_EXIT}")
            return False
        if rule not in rules:
            got = sorted(rules)
            print(f"FAIL  {label}: exit {code}, but rule {rule!r} did not fire (got {got})")
            return False
        print(f"ok    {label}: caught by {rule} (exit {code})")
        return True


def real_history_clean() -> bool:
    code, rules, where = run_gitleaks(REPO)
    if code == 0:
        print("ok    real history scans clean")
        return True
    if code == LEAK_EXIT:
        print(f"FAIL  real history has findings: {sorted(rules)}")
        for w in where:
            print(f"        {w}")
    else:
        print(f"FAIL  gitleaks exited {code} on the real history: a scanner error, not clean")
    return False


def main() -> int:
    if shutil.which("gitleaks") is None:
        print("FAIL  gitleaks is not on PATH; this gate cannot be verified, so it fails")
        return 1
    version = subprocess.run(
        ["gitleaks", "version"], capture_output=True, text=True, check=False
    ).stdout.strip()
    skew = version.lstrip("v") != GITLEAKS_PINNED
    print(f"gitleaks {version or 'unknown'} (CI pins {GITLEAKS_PINNED})")

    # Every planted probe first, and stop before the clean check if any failed. A clean result
    # printed under a gate that just showed it cannot fire is reassurance from nothing.
    ok = all([probe(*p) for p in PROBES])
    if ok:
        ok = real_history_clean()
    if skew:
        print(
            f"NOTE  this ran on gitleaks {version or 'unknown'}, not {GITLEAKS_PINNED}. "
            "Rulesets differ; the verdict that counts is CI's."
        )
    print("gate verified two-sided" if ok else "gate NOT verified")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
