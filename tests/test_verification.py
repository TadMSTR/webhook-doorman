"""Verification, one negative test per strategy — this is the point of the project.

The positive cases are cheap. The cases that matter are the ones where a plausible-looking
implementation says yes: an empty secret, a blank header, a signature computed over a
re-serialised body, a peer outside the allowlist.
"""

from __future__ import annotations

import base64
import json

import pytest

from webhook_doorman.config import BasicVerify, BearerVerify, HmacVerify, NoneVerify
from webhook_doorman.verification import (
    verify,
    verify_basic,
    verify_bearer,
    verify_hmac,
    verify_peer,
)

from .conftest import GITHUB_SECRET, sign_b64, sign_hex

BODY = b'{"action":"opened","number":7}'

GITHUB_SPEC = HmacVerify(
    strategy="hmac_sha256",
    header="X-Hub-Signature-256",
    prefix="sha256=",
    encoding="hex",
    secret_env="GITHUB_WEBHOOK_SECRET",
)
BARE_HEX_SPEC = HmacVerify(
    strategy="hmac_sha256",
    header="X-Vikunja-Signature",
    secret_env="VIKUNJA_WEBHOOK_SECRET",
)
B64_SPEC = HmacVerify(
    strategy="hmac_sha256",
    header="X-Signature",
    encoding="base64",
    secret_env="SOME_SECRET",
)


class TestHmac:
    def test_valid_signature_accepted(self):
        header = sign_hex(GITHUB_SECRET, BODY, "sha256=")
        assert verify_hmac(GITHUB_SPEC, BODY, header, GITHUB_SECRET).ok

    def test_bare_hex_variant_accepted(self):
        header = sign_hex(GITHUB_SECRET, BODY)
        assert verify_hmac(BARE_HEX_SPEC, BODY, header, GITHUB_SECRET).ok

    def test_base64_encoding_accepted(self):
        header = sign_b64(GITHUB_SECRET, BODY)
        assert verify_hmac(B64_SPEC, BODY, header, GITHUB_SECRET).ok

    def test_empty_secret_never_matches(self):
        """Fail closed even if the caller forgot to check the secret was set."""
        result = verify_hmac(GITHUB_SPEC, BODY, sign_hex("", BODY, "sha256="), "")
        assert not result.ok
        assert result.reason == "secret is unset"

    def test_missing_header_rejected(self):
        assert not verify_hmac(GITHUB_SPEC, BODY, "", GITHUB_SECRET).ok

    def test_blank_header_rejected(self):
        assert not verify_hmac(GITHUB_SPEC, BODY, "   ", GITHUB_SECRET).ok

    def test_wrong_secret_rejected(self):
        header = sign_hex("some-other-secret-value", BODY, "sha256=")
        assert not verify_hmac(GITHUB_SPEC, BODY, header, GITHUB_SECRET).ok

    def test_missing_prefix_rejected(self):
        header = sign_hex(GITHUB_SECRET, BODY)  # correct digest, no "sha256="
        result = verify_hmac(GITHUB_SPEC, BODY, header, GITHUB_SECRET)
        assert not result.ok
        assert result.reason == "signature prefix mismatch"

    def test_tampered_body_rejected(self):
        header = sign_hex(GITHUB_SECRET, BODY, "sha256=")
        assert not verify_hmac(GITHUB_SPEC, BODY + b" ", header, GITHUB_SECRET).ok

    def test_signature_is_over_raw_bytes_not_reserialised_json(self):
        """A re-serialised body must not verify.

        json.dumps changes whitespace and key order. If this passed, the implementation would be
        signing a normalised form and an attacker could reorder keys freely.
        """
        reserialised = json.dumps(json.loads(BODY), indent=2).encode()
        header = sign_hex(GITHUB_SECRET, BODY, "sha256=")
        assert not verify_hmac(GITHUB_SPEC, reserialised, header, GITHUB_SECRET).ok

    def test_encoding_mismatch_rejected(self):
        """A hex digest presented to a base64 source must not match."""
        header = sign_hex(GITHUB_SECRET, BODY)
        assert not verify_hmac(B64_SPEC, BODY, header, GITHUB_SECRET).ok


BEARER_SPEC = BearerVerify(strategy="bearer", secret_env="TOKEN")


class TestBearer:
    def test_valid_token_accepted(self):
        assert verify_bearer(BEARER_SPEC, "Bearer abcdefgh12345678", "abcdefgh12345678").ok

    def test_empty_secret_never_matches(self):
        assert not verify_bearer(BEARER_SPEC, "Bearer ", "").ok

    def test_missing_header_rejected(self):
        assert not verify_bearer(BEARER_SPEC, "", "abcdefgh12345678").ok

    def test_wrong_token_rejected(self):
        assert not verify_bearer(BEARER_SPEC, "Bearer wrong-token-value", "abcdefgh12345678").ok

    def test_missing_scheme_rejected(self):
        assert not verify_bearer(BEARER_SPEC, "abcdefgh12345678", "abcdefgh12345678").ok

    def test_custom_header_and_prefix(self):
        spec = BearerVerify(strategy="bearer", secret_env="T", header="X-Token", prefix="")
        assert verify_bearer(spec, "abcdefgh12345678", "abcdefgh12345678").ok


BASIC_SPEC = BasicVerify(strategy="basic", user_env="U", pass_env="P")


def basic_header(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class TestBasic:
    def test_valid_credentials_accepted(self):
        assert verify_basic(
            BASIC_SPEC, basic_header("alice", "s3cret-value"), "alice", "s3cret-value"
        ).ok

    def test_wrong_password_rejected(self):
        assert not verify_basic(
            BASIC_SPEC, basic_header("alice", "nope"), "alice", "s3cret-value"
        ).ok

    def test_wrong_user_rejected(self):
        assert not verify_basic(
            BASIC_SPEC, basic_header("mallory", "s3cret-value"), "alice", "s3cret-value"
        ).ok

    def test_unset_credentials_never_match(self):
        assert not verify_basic(BASIC_SPEC, basic_header("", ""), "", "").ok

    def test_missing_header_rejected(self):
        assert not verify_basic(BASIC_SPEC, "", "alice", "s3cret-value").ok

    def test_wrong_scheme_rejected(self):
        assert not verify_basic(BASIC_SPEC, "Bearer abcdefgh", "alice", "s3cret-value").ok

    def test_malformed_base64_rejected(self):
        assert not verify_basic(BASIC_SPEC, "Basic !!!not-base64!!!", "alice", "s3cret-value").ok

    def test_missing_colon_rejected(self):
        encoded = base64.b64encode(b"alice").decode()
        assert not verify_basic(BASIC_SPEC, f"Basic {encoded}", "alice", "s3cret-value").ok


NONE_SPEC = NoneVerify(
    strategy="none",
    unverified_reason="loopback-only producer",
    allow_from=["127.0.0.1/32", "10.9.0.0/24"],
)


class TestNonePeerAllowlist:
    def test_loopback_peer_accepted(self):
        assert verify_peer(NONE_SPEC, "127.0.0.1").ok

    def test_peer_in_cidr_accepted(self):
        assert verify_peer(NONE_SPEC, "10.9.0.17").ok

    def test_peer_outside_allowlist_rejected(self):
        result = verify_peer(NONE_SPEC, "10.9.1.17")
        assert not result.ok
        assert "not in allow_from" in result.reason

    def test_missing_peer_rejected(self):
        assert not verify_peer(NONE_SPEC, None).ok

    def test_unparseable_peer_rejected(self):
        assert not verify_peer(NONE_SPEC, "not-an-address").ok

    def test_ipv6_peer_does_not_match_ipv4_cidr(self):
        assert not verify_peer(NONE_SPEC, "::1").ok

    def test_ipv6_allowlist_matches_ipv6_peer(self):
        spec = NoneVerify(strategy="none", unverified_reason="r", allow_from=["::1/128"])
        assert verify_peer(spec, "::1").ok


class TestDispatch:
    @pytest.mark.parametrize(
        ("spec", "headers", "secrets", "expected"),
        [
            (
                GITHUB_SPEC,
                {"x-hub-signature-256": sign_hex(GITHUB_SECRET, BODY, "sha256=")},
                {"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET},
                True,
            ),
            (GITHUB_SPEC, {}, {"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET}, False),
            (GITHUB_SPEC, {"x-hub-signature-256": "sha256=deadbeef"}, {}, False),
            (
                BEARER_SPEC,
                {"authorization": "Bearer abcdefgh12345678"},
                {"TOKEN": "abcdefgh12345678"},
                True,
            ),
            (BEARER_SPEC, {"authorization": "Bearer nope"}, {"TOKEN": "abcdefgh12345678"}, False),
        ],
    )
    def test_dispatch(self, spec, headers, secrets, expected):
        assert verify(spec, body=BODY, headers=headers, peer=None, secrets=secrets).ok is expected

    def test_header_lookup_is_case_insensitive_via_lowercased_keys(self):
        headers = {"x-hub-signature-256": sign_hex(GITHUB_SECRET, BODY, "sha256=")}
        assert verify(
            GITHUB_SPEC,
            body=BODY,
            headers=headers,
            peer=None,
            secrets={"GITHUB_WEBHOOK_SECRET": GITHUB_SECRET},
        ).ok

    def test_none_strategy_dispatches_to_peer_check(self):
        assert verify(NONE_SPEC, body=b"", headers={}, peer="127.0.0.1", secrets={}).ok
        assert not verify(NONE_SPEC, body=b"", headers={}, peer="8.8.8.8", secrets={}).ok

    def test_unknown_strategy_object_fails_closed(self):
        """A future config shape must never fall through to accepted."""

        class Unknown:
            strategy = "future"

        assert not verify(Unknown(), body=b"", headers={}, peer="127.0.0.1", secrets={}).ok
