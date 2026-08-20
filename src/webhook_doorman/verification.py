"""Request verification. Every path in this module fails closed.

Lifted from `vikunja-webhook-listener`'s `security.py`, whose design note is worth restating
because it is the reason this project exists: a sibling service verified signatures with

    if not SECRET:
        return True  # no secret configured, skip verification

on an internet-reachable endpoint. "Verification skipped" is the outcome that must never be
reachable. Here an absent secret is handled one layer up as *source disabled → reject*, and every
function below still returns False for an empty secret, so even a misordered call fails closed.

Invariants, each with a negative test in `tests/test_verification.py`:

* HMAC is computed over the **raw bytes** as received. The body is never re-serialised and
  compared — a JSON round-trip changes whitespace and key order, and a signature that survives
  that is not a signature.
* Every comparison is `hmac.compare_digest`. No `==` on a credential anywhere.
* A missing or blank credential header never matches, including against an empty secret.
* `none` sources match the socket peer against a CIDR allowlist, never a forwarded-for header.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
from dataclasses import dataclass

from .config import BasicVerify, BearerVerify, HmacVerify, NoneVerify, VerifySpec


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying one request.

    `reason` is for the operator's log, never for the response body — telling a caller *why*
    its signature failed helps an attacker more than it helps a developer.
    """

    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


_OK = VerificationResult(True)


def _digest(secret: str, body: bytes, encoding: str) -> str:
    raw = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if encoding == "base64":
        return base64.b64encode(raw).decode("ascii")
    return raw.hex()


def verify_hmac(spec: HmacVerify, body: bytes, presented: str, secret: str) -> VerificationResult:
    """Verify an HMAC-SHA256 signature header over the raw body."""
    if not secret:
        return VerificationResult(False, "secret is unset")
    if not presented:
        return VerificationResult(False, f"missing {spec.header} header")
    if spec.prefix and not presented.startswith(spec.prefix):
        return VerificationResult(False, "signature prefix mismatch")

    expected = spec.prefix + _digest(secret, body, spec.encoding)
    if not hmac.compare_digest(expected, presented):
        return VerificationResult(False, "signature mismatch")
    return _OK


def verify_bearer(spec: BearerVerify, presented: str, secret: str) -> VerificationResult:
    """Verify a shared bearer token."""
    if not secret:
        return VerificationResult(False, "secret is unset")
    if not presented:
        return VerificationResult(False, f"missing {spec.header} header")

    expected = spec.prefix + secret
    if not hmac.compare_digest(expected, presented):
        return VerificationResult(False, "token mismatch")
    return _OK


def verify_basic(spec: BasicVerify, presented: str, user: str, password: str) -> VerificationResult:
    """Verify HTTP Basic credentials.

    Both halves are compared even when the username already failed, so the work done is
    independent of which half is wrong.
    """
    if not user or not password:
        return VerificationResult(False, "credentials are unset")
    if not presented:
        return VerificationResult(False, f"missing {spec.header} header")

    scheme, _, encoded = presented.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return VerificationResult(False, "not a Basic credential")

    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return VerificationResult(False, "malformed Basic credential")

    presented_user, sep, presented_pass = decoded.partition(":")
    if not sep:
        return VerificationResult(False, "malformed Basic credential")

    user_ok = hmac.compare_digest(user, presented_user)
    pass_ok = hmac.compare_digest(password, presented_pass)
    if not (user_ok and pass_ok):
        return VerificationResult(False, "credential mismatch")
    return _OK


def verify_peer(spec: NoneVerify, peer: str | None) -> VerificationResult:
    """Match an unverified source's socket peer against its CIDR allowlist.

    `peer` must be the transport-level client address. Passing a value derived from
    `X-Forwarded-For` would make this allowlist forgeable by the caller it is meant to constrain.
    """
    if not peer:
        return VerificationResult(False, "peer address unavailable")
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return VerificationResult(False, f"unparseable peer address {peer!r}")

    for network in spec.networks():
        if address.version == network.version and address in network:
            return _OK
    return VerificationResult(False, f"peer {peer} not in allow_from")


def verify(
    spec: VerifySpec,
    *,
    body: bytes,
    headers: dict[str, str],
    peer: str | None,
    secrets: dict[str, str],
) -> VerificationResult:
    """Dispatch to the configured strategy.

    Args:
        spec: the source's `verify:` block.
        body: raw request body, exactly as received.
        headers: request headers, **lowercased keys**.
        peer: socket peer address, or None if unavailable.
        secrets: resolved environment values, keyed by variable name.

    Returns:
        A `VerificationResult`. Any unrecognised strategy returns False rather than raising,
        so a future config shape can never fall through to "accepted".
    """
    if isinstance(spec, HmacVerify):
        return verify_hmac(
            spec,
            body,
            headers.get(spec.header.lower(), ""),
            secrets.get(spec.secret_env, ""),
        )
    if isinstance(spec, BearerVerify):
        return verify_bearer(
            spec,
            headers.get(spec.header.lower(), ""),
            secrets.get(spec.secret_env, ""),
        )
    if isinstance(spec, BasicVerify):
        return verify_basic(
            spec,
            headers.get(spec.header.lower(), ""),
            secrets.get(spec.user_env, ""),
            secrets.get(spec.pass_env, ""),
        )
    if isinstance(spec, NoneVerify):
        return verify_peer(spec, peer)
    return VerificationResult(False, f"unknown verification strategy {spec!r}")
