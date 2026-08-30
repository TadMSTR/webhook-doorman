"""The shipped example configs must be valid.

These are documentation people copy. A broken example is a broken quickstart, and it is the kind
of rot nothing else catches: examples are edited by hand, and a config schema change does not
touch them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from webhook_doorman.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((REPO_ROOT / "examples").glob("*.yml"))
ALL_CONFIGS = [REPO_ROOT / "config.example.yml", *EXAMPLES]


def test_examples_directory_is_not_empty():
    """Guard the parametrisation below: zero files would make every test vacuously pass."""
    assert EXAMPLES, "examples/ contains no .yml files"


@pytest.mark.parametrize("path", ALL_CONFIGS, ids=lambda p: p.name)
def test_config_loads(path: Path):
    config = load_config(path)
    assert config.sources
    assert config.sinks


@pytest.mark.parametrize("path", ALL_CONFIGS, ids=lambda p: p.name)
def test_every_referenced_sink_exists(path: Path):
    config = load_config(path)
    known = {s.name for s in config.sinks}
    for source in config.sources:
        assert set(source.sinks) <= known


@pytest.mark.parametrize("path", ALL_CONFIGS, ids=lambda p: p.name)
def test_no_inline_secrets(path: Path):
    """Credentials are referenced by variable name. An example that inlines one teaches the
    opposite of the design."""
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not re.match(r"^\s*(secret|token|password|pass|api_key)\s*:", stripped), (
            f"{path.name}: inline credential field in {stripped!r} — use a *_env reference"
        )


# Real values that must never appear in a public repo. Matching by shape, not by a specific
# deployment's values, so this stays useful to anyone who forks it.
FORBIDDEN = [
    (r"![A-Za-z0-9]{16,}:[A-Za-z0-9.-]+\.[a-z]{2,}", "a real-looking Matrix room ID"),
    (r"\bsyt_[A-Za-z0-9_-]{20,}", "a Matrix access token"),
    (r"\bgh[pousr]_[A-Za-z0-9]{16,}", "a GitHub token"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "an RFC1918 address"),
    (r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "an RFC1918 address"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "an RFC1918 address"),
]

DOCS = [
    *ALL_CONFIGS,
    REPO_ROOT / "README.md",
    REPO_ROOT / "ARCHITECTURE.md",
    REPO_ROOT / "docs" / "deployment.md",
    REPO_ROOT / "docker-compose.yml",
    REPO_ROOT / ".env.example",
]


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.name)
def test_no_real_topology_in_public_docs(path: Path):
    """This repo is public. Examples and docs are where a real hostname or address slips in.

    Precedent: a sibling project leaked five Matrix room IDs into public git history and needed
    `filter-repo` to clean up. A committed value stays in the history whatever the next commit
    does, so this runs on every PR rather than at review time.
    """
    text = path.read_text(encoding="utf-8")
    for pattern, description in FORBIDDEN:
        match = re.search(pattern, text)
        assert match is None, f"{path.name} contains {description}: {match.group(0)!r}"


def test_the_agent_example_renders_valid_json():
    """The agent-facing example is the one a reader copies for an LLM destination.

    `test_config_loads` proves the YAML parses; it does not prove the template in it works. This
    renders that sink's body against a fenced context and parses the result — the failure it
    exists to catch is a template that is valid YAML, valid Jinja, and produces broken JSON the
    moment a payload contains a quote.
    """
    import json as _json

    from webhook_doorman.fencing import fence_context
    from webhook_doorman.templating import render

    config = load_config(REPO_ROOT / "examples" / "github-to-agent.yml")
    sink = config.sink_by_name("agent-inbox")
    assert sink is not None and sink.agent_readable is True

    context = fence_context(
        {
            "event_id": 12,
            "repo": "o/r",
            "number": 7,
            "url": "https://example.invalid/7",
            "title": "t",
            "body": 'a "quoted" body\nwith </untrusted> in it',
        },
        source="github",
        fields=["summary", "title", "body", "author"],
    )
    rendered = _json.loads(render(sink.template, context))

    assert rendered["event_id"] == 12
    assert rendered["repo"] == "o/r"
    assert rendered["content"].startswith('<untrusted source="github" field="body">')
    assert rendered["content"].count("</untrusted>") == 1


def test_the_declared_version_is_the_same_number_everywhere():
    """`pyproject.toml`, `__init__.py`, the changelog and the compose tag are four rosters of
    one fact, and a release that bumps three of them ships a container reporting the fourth.

    Read from `pyproject.toml` rather than `importlib.metadata`, which reports whatever was last
    installed into the venv and can be stale against the working tree.
    """
    import tomllib

    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        declared = tomllib.load(handle)["project"]["version"]

    from webhook_doorman import __version__

    assert __version__ == declared

    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{declared}]" in changelog, "the changelog has no section for this version"
    assert f"[{declared}]: https://" in changelog, "the changelog has no release link"

    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert f"webhook-doorman:{declared}" in compose
