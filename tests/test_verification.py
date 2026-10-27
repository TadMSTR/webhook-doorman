"""Verification, one negative test per strategy — this is the point of the project.

The positive cases are cheap. The cases that matter are the ones where a plausible-looking
implementation says yes: an empty secret, a blank header, a signature computed over a
re-serialised body, a peer outside the allowlist.
"""

from __future__ import annotations

import ast
import base64
import json
import re
from pathlib import Path

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


class TestBlankHeaderReason:
    """A blank header is reported as missing, not as a bad signature.

    The verdict is the same either way, so only the reason pins the guard. The reason is what an
    operator reads in `verification_failed` to tell a misconfigured producer that sends no
    header from one that signs with the wrong secret.
    """

    def test_hmac_without_prefix(self):
        result = verify_hmac(BARE_HEX_SPEC, BODY, "", "some-secret")
        assert result.reason == "missing X-Vikunja-Signature header"


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


# ------------------------------------------------------------------------------------------
# Non-ASCII credentials (fingerprint e191bc2b).
#
# `hmac.compare_digest` accepts two `str` values only when both are ASCII and raises TypeError
# otherwise. A header is attacker-controlled, so `Bearer \xe9` reached it and became a 500 with a
# traceback, bypassing the `verification_failed` log line and the failure counter. A credential
# is compared as UTF-8 bytes now, so non-ASCII is an ordinary mismatch, or an ordinary match when
# the configured secret is itself non-ASCII.
# ------------------------------------------------------------------------------------------


class TestNonAsciiCredentials:
    def test_non_ascii_bearer_is_a_mismatch_not_an_exception(self):
        result = verify_bearer(BEARER_SPEC, "Bearer \xe9", "abcdefgh12345678")
        assert not result.ok
        assert result.reason == "token mismatch"

    def test_non_ascii_hmac_signature_is_a_mismatch_not_an_exception(self):
        result = verify_hmac(GITHUB_SPEC, BODY, "sha256=\xff", GITHUB_SECRET)
        assert not result.ok
        assert result.reason == "signature mismatch"

    def test_non_ascii_basic_credential_is_a_mismatch_not_an_exception(self):
        header = basic_header("jürgen", "päss")
        result = verify_basic(BASIC_SPEC, header, "alice", "s3cret-value")
        assert not result.ok
        assert result.reason == "credential mismatch"

    def test_a_non_ascii_configured_credential_can_still_match(self):
        """Bytes, not a refusal: an operator's non-ASCII password is a valid password."""
        header = basic_header("jürgen", "päss-NOTREAL")
        assert verify_basic(BASIC_SPEC, header, "jürgen", "päss-NOTREAL").ok
        assert verify_bearer(BEARER_SPEC, "Bearer töken", "töken").ok

    @pytest.mark.parametrize(
        ("spec", "headers", "secrets"),
        [
            (GITHUB_SPEC, {"x-hub-signature-256": "sha256=\xff"}, {"GITHUB_WEBHOOK_SECRET": "s"}),
            (BEARER_SPEC, {"authorization": "Bearer \xe9"}, {"TOKEN": "abcdefgh12345678"}),
        ],
    )
    def test_dispatch_never_raises_on_non_ascii(self, spec, headers, secrets):
        assert not verify(spec, body=BODY, headers=headers, peer=None, secrets=secrets).ok


class TestBasicEdges:
    """Branches mutation testing showed no test could tell from their removal."""

    def test_an_unset_username_is_not_matched_by_an_empty_one(self):
        """`or`, not `and`: one half unset is unset, even if the caller sends an empty user."""
        assert not verify_basic(BASIC_SPEC, basic_header("", "s3cret-value"), "", "s3cret-value")

    def test_a_basic_payload_under_another_scheme_is_refused(self):
        encoded = basic_header("alice", "s3cret-value").removeprefix("Basic ")
        assert not verify_basic(BASIC_SPEC, f"Bearer {encoded}", "alice", "s3cret-value")

    def test_a_password_may_contain_a_colon(self):
        """RFC 7617: the user-id cannot contain ':', the password can. Split on the first."""
        assert verify_basic(BASIC_SPEC, basic_header("alice", "s3:cr:et"), "alice", "s3:cr:et")


class TestBasicDispatch:
    """`verify` must hand the configured user and password to the right halves (ad8bdc8e).

    Every basic case in `TestDispatch` was missing, so swapping `user_env` and `pass_env` in the
    dispatcher, or replacing the whole arm with an accept, left the suite green.
    """

    SECRETS = {"U": "alice", "P": "s3cret-value"}  # noqa: RUF012

    def test_correct_credentials_accepted(self):
        headers = {"authorization": basic_header("alice", "s3cret-value")}
        assert verify(BASIC_SPEC, body=b"", headers=headers, peer=None, secrets=self.SECRETS).ok

    def test_credentials_presented_swapped_are_rejected(self):
        headers = {"authorization": basic_header("s3cret-value", "alice")}
        assert not verify(BASIC_SPEC, body=b"", headers=headers, peer=None, secrets=self.SECRETS).ok

    def test_no_header_is_rejected(self):
        assert not verify(BASIC_SPEC, body=b"", headers={}, peer=None, secrets=self.SECRETS).ok


# ------------------------------------------------------------------------------------------
# No `==` on a credential, anywhere (#759, fingerprint 774f911b).
#
# Replacing `compare_digest` with `!=` in `verify_hmac` survived the whole suite: every
# behavioural test passes either way, because a timing side channel is not observable in a unit
# test. So this is a structural test. Every constant-time comparison goes through
# `secure_compare`, and nothing else in the package may compare a credential-named value with
# `==` or `!=`. Read from the source by AST, so a comment or string cannot satisfy it.
# ------------------------------------------------------------------------------------------

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "webhook_doorman"

#: Identifiers that hold, or are derived from, a credential. Matched against variable names,
#: attribute names and the last segment of a dotted name.
CREDENTIAL_NAME = re.compile(
    r"(secret|token|password|passwd|signature|digest|credential|expected|presented"
    r"|^user$|^pass$|presented_user|presented_pass)",
    re.IGNORECASE,
)


def _modules() -> list[Path]:
    files = sorted(PACKAGE.rglob("*.py"))
    assert len(files) >= 20, f"only {len(files)} modules found under {PACKAGE}: wrong path?"
    return files


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return None


def _calls_compare_digest(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _name_of(node.func) == "compare_digest"


class TestConstantTimeComparison:
    def test_nothing_compares_a_credential_with_eq_or_ne(self):
        offenders = []
        for path in _modules():
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                    continue
                for operand in (node.left, *node.comparators):
                    name = _name_of(operand)
                    if name and CREDENTIAL_NAME.search(name):
                        offenders.append(f"{path.name}:{node.lineno} {ast.unparse(node)}")
        assert offenders == [], "credential compared with ==/!=:\n" + "\n".join(offenders)

    def test_compare_digest_is_called_only_inside_secure_compare(self):
        """One choke point, so the bytes conversion and the constant-time call cannot drift."""
        sites: set[str] = set()
        for path in _modules():
            tree = ast.parse(path.read_text(), filename=str(path))
            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if func.name == "secure_compare" and path.name == "verification.py":
                    continue
                for node in ast.walk(func):
                    if _calls_compare_digest(node):
                        sites.add(f"{path.name}:{node.lineno}")
        assert not sites, "compare_digest outside secure_compare:\n" + "\n".join(sorted(sites))

    def test_secure_compare_is_constant_time_and_bytes(self):
        tree = ast.parse((PACKAGE / "verification.py").read_text())
        funcs = [
            f
            for f in ast.walk(tree)
            if isinstance(f, ast.FunctionDef) and f.name == "secure_compare"
        ]
        assert len(funcs) == 1, "verification.secure_compare is missing"
        body = list(ast.walk(funcs[0]))
        assert any(_calls_compare_digest(n) for n in body), "secure_compare must use compare_digest"
        assert not any(
            isinstance(n, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in n.ops)
            for n in body
        ), "secure_compare must not use ==/!="

    @pytest.mark.parametrize(
        ("module", "function"),
        [
            ("verification.py", "verify_hmac"),
            ("verification.py", "verify_bearer"),
            ("verification.py", "verify_basic"),
            ("engine.py", "check_admin_token"),
            ("app.py", "metrics"),
        ],
    )
    def test_every_credential_check_calls_secure_compare(self, module, function):
        """The roster of places that compare a credential. A new one must be added here."""
        tree = ast.parse((PACKAGE / module).read_text())
        funcs = [
            f
            for f in ast.walk(tree)
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == function
        ]
        assert funcs, f"{module}:{function} not found"
        assert any(
            isinstance(n, ast.Call) and _name_of(n.func) == "secure_compare"
            for n in ast.walk(funcs[0])
        ), f"{module}:{function} does not call secure_compare"

    def test_the_structural_test_can_fail(self):
        """The control: the scan must flag the exact mutation #759 describes."""
        mutated = "def f(expected, presented):\n    if expected != presented:\n        return 1\n"
        hits = [
            n
            for n in ast.walk(ast.parse(mutated))
            if isinstance(n, ast.Compare)
            and any(CREDENTIAL_NAME.search(_name_of(o) or "") for o in (n.left, *n.comparators))
        ]
        assert hits
