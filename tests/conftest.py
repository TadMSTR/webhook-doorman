"""Shared fixtures.

Every secret here is invented. Nothing in this directory is a real credential, a real host or a
real room ID — this repo is public, and the fixtures are the easiest place for topology to leak
in without anyone noticing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import socket
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


_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "testserver", ""}


@pytest.fixture(autouse=True)
def no_network_egress(monkeypatch):
    """A test may not leave the machine. Resolving or connecting anywhere but loopback fails it.

    Every sink test goes through `pytest-httpx` or the ASGI test client, neither of which opens
    a socket, and the tracing harness listens on 127.0.0.1 on purpose. Anything else is a test
    that depends on the network, or one that leaks to it, as the tracing tests once did.
    """
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    # Recorded as well as raised: an exporter's background thread catches the exception and
    # retries quietly, and the test would pass. Teardown fails it instead.
    attempts: list[str] = []

    def getaddrinfo(host, *args, **kwargs):
        name = host.decode() if isinstance(host, bytes) else (host or "")
        if name not in _LOCAL_NAMES:
            attempts.append(f"DNS lookup for {name!r}")
            raise AssertionError(f"test attempted a DNS lookup for {name!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0]
            if host not in _LOCAL_NAMES and not ipaddress.ip_address(host).is_loopback:
                attempts.append(f"connection to {address!r}")
                raise AssertionError(f"test attempted a connection to {address!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    yield
    assert not attempts, f"test attempted network egress: {attempts}"
