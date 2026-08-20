"""Strip credentials before anything is written to disk or a log.

The event log is the one genuinely new risk this design introduces. The listeners it replaces
kept nothing; this one keeps every request on a mounted volume so it can dedup, retry and replay.
Persist a signature header verbatim and that volume quietly becomes a secret store — one an
operator will back up, copy to a NAS, and never think of as sensitive.

The fix is redaction **at write time**, not encryption at rest. Encryption moves the problem to
key handling and tends to end the way notify-proxy's did: a Fernet-encrypted column sitting
beside plaintext bot tokens, flagged in its own README. Don't store the secret and there is
nothing to encrypt.

Two passes, because credentials arrive by two routes:

* **By name** — headers that are credentials by definition (`Authorization`, `Cookie`) plus the
  specific header a source's verify block names. These are redacted whatever they contain.
* **By value** — every resolved secret, matched as a substring anywhere in a header value or the
  body. This catches the case the name-based pass cannot: a producer that echoes a token into a
  field nobody anticipated.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

REDACTED = "<redacted>"

# Redacted on name alone, regardless of value. Lowercase — callers pass lowercased keys.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-authorization",
        "x-vikunja-signature",
        "x-hub-signature",
        "x-hub-signature-256",
        "x-gitlab-token",
        "x-webhook-signature",
    }
)

# A short "secret" would match everywhere and turn redaction into corruption. Anything this
# short is not protecting the endpoint in the first place, so leaving it unmatched by the
# value pass costs nothing real.
MIN_REDACTABLE_LENGTH = 8


def _redactable(secret_values: Iterable[str]) -> list[str]:
    # Longest first, so an overlapping shorter secret cannot leave a fragment behind.
    return sorted(
        {v for v in secret_values if v and len(v) >= MIN_REDACTABLE_LENGTH},
        key=len,
        reverse=True,
    )


def redact_text(text: str, secret_values: Iterable[str]) -> str:
    """Replace every occurrence of a known secret value in `text`."""
    for value in _redactable(secret_values):
        text = text.replace(value, REDACTED)
    return text


def redact_bytes(body: bytes, secret_values: Iterable[str]) -> bytes:
    """Same as `redact_text`, for a raw body that is stored for replay.

    A body containing a live credential is redacted even though that changes what a replay
    delivers. A replayed event that is missing a token is a visible failure an operator can
    fix; a token sitting in a backed-up SQLite file is not.
    """
    for value in _redactable(secret_values):
        encoded = value.encode("utf-8", errors="ignore")
        if encoded and encoded in body:
            body = body.replace(encoded, REDACTED.encode("ascii"))
    return body


def redact_headers(
    headers: Mapping[str, str],
    *,
    extra_headers: Iterable[str] = (),
    secret_values: Iterable[str] = (),
) -> dict[str, str]:
    """Return a copy of `headers` safe to persist.

    Args:
        headers: request headers with lowercased keys.
        extra_headers: header names this source treats as a credential — the `header` field of
            its verify block. Case-insensitive.
        secret_values: resolved secret values, redacted wherever they appear as a substring.

    Returns:
        A new dict. The input is never mutated, so a caller that still needs the real
        `Authorization` header for an upstream call is unaffected.
    """
    by_name = SENSITIVE_HEADERS | {h.lower() for h in extra_headers if h}
    values = _redactable(secret_values)

    out: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in by_name:
            out[key] = REDACTED
            continue
        for secret in values:
            if secret in value:
                value = value.replace(secret, REDACTED)
        out[key] = value
    return out
