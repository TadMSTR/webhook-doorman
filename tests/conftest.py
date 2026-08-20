"""Shared fixtures.

Every secret here is invented. Nothing in this directory is a real credential, a real host or a
real room ID — this repo is public, and the fixtures are the easiest place for topology to leak
in without anyone noticing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path

import pytest
import yaml

GITHUB_SECRET = "test-github-secret-0123456789abcdef"
BEARER_SECRET = "test-bearer-token-0123456789abcdef"
ADMIN_TOKEN = "test-admin-token-0123456789abcdefghij"


def sign_hex(secret: str, body: bytes, prefix: str = "") -> str:
    """Produce the header value an HMAC-hex source expects."""
    return prefix + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def sign_b64(secret: str, body: bytes, prefix: str = "") -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return prefix + base64.b64encode(digest).decode("ascii")


BASE_CONFIG: dict = {
    "server": {"max_body_bytes": 4096},
    "sources": [
        {
            "name": "github",
            "path": "/webhook/github",
            "parser": "github",
            "verify": {
                "strategy": "hmac_sha256",
                "header": "X-Hub-Signature-256",
                "prefix": "sha256=",
                "encoding": "hex",
                "secret_env": "GITHUB_WEBHOOK_SECRET",
            },
            "dedup": {"id_header": "X-GitHub-Delivery"},
            "sinks": ["notes"],
        },
        {
            "name": "internal",
            "path": "/webhook/internal",
            "verify": {
                "strategy": "bearer",
                "secret_env": "INTERNAL_TOKEN",
            },
            "sinks": ["notes"],
        },
    ],
    "sinks": [
        {
            "name": "notes",
            "type": "http",
            "url": "https://sink.example.invalid/notes",
            "template": '{"text": "{{ summary }}"}',
        }
    ],
}


BASE_ENV = {
    "GITHUB_WEBHOOK_SECRET": GITHUB_SECRET,
    "INTERNAL_TOKEN": BEARER_SECRET,
}


@pytest.fixture
def base_config() -> dict:
    """A deep-enough copy that a test can mutate it freely."""
    import copy

    return copy.deepcopy(BASE_CONFIG)


@pytest.fixture
def base_env() -> dict[str, str]:
    return dict(BASE_ENV)


@pytest.fixture
def write_config(tmp_path: Path):
    """Write a config dict to a temp file and return its path."""

    def _write(data: dict, name: str = "config.yml") -> Path:
        path = tmp_path / name
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return path

    return _write
