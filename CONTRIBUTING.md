# Contributing

Thanks for looking. This is a small project with a narrow purpose, so the most useful thing to
read before writing code is the "Decisions" section of [ARCHITECTURE.md](ARCHITECTURE.md) — most
of what looks like an obvious improvement was considered and rejected for a reason worth knowing.

## Getting set up

```bash
git clone https://github.com/TadMSTR/webhook-doorman
cd webhook-doorman
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

pytest
ruff check . && ruff format --check .
```

Python 3.11 is the floor. CI runs 3.11, 3.12 and 3.13.

## The bar

**Verification strictness is not negotiable.** A change that trades it for convenience will be
declined, however reasonable the convenience. In particular:

- No code path may accept a request when its secret is missing or empty.
- No `==` on a credential. `hmac.compare_digest`, always.
- HMAC covers the raw request bytes, before decoding.
- A verification failure returns 401 with no detail. The reason goes to the log.
- Credentials are redacted before anything reaches storage or a log.

Each of those has a negative test. Deleting the test is deleting the invariant, and a PR that
does it will be asked why.

## Adding things

**A source** is a `config.yml` entry, not code. If you need to edit Python to support a producer,
that is a gap in the abstraction — please open an issue describing the producer, so the gap gets
fixed rather than worked around.

**A verification strategy:** a model in `config.py` added to the `VerifySpec` union, a function in
`verification.py`, a branch in `verify()`. Leave the fallthrough returning `False`. Negative tests
for empty secret, missing header, and wrong credential.

**A sink:** a model added to the `SinkSpec` union, a class in `sinks/`, an entry in `_BUILDERS`.
Raise `PermanentSinkError` when a retry cannot possibly help (4xx, bad template) and `SinkError`
when it can (5xx, timeout). Getting that backwards either burns five attempts on a guaranteed
failure or throws away a recoverable one. If the destination overloads a status code — Apprise
answers `204` for "I notified nothing" — override `_classify` rather than special-casing it
inside `deliver`.

Two things to decide before writing the model:

- **Does the endpoint URL contain a credential?** If it does, as Discord's and Slack's webhook
  URLs do, **do not inherit `_EndpointMixin`.** Its inline `url` form exists because a plain
  endpoint is topology rather than a secret; offering it for a URL that embeds a token invites
  committing a live credential to `config.yml`, and keeps that value out of the redaction set.
  Use a single required `webhook_url_env` instead. Any field ending in `_env` is discovered
  automatically — there is no second place to register it.
- **How does the destination render your text?** Escaping belongs to the sink, because only the
  sink knows the rendering context. `render()` for plain text and markdown, `render_html()` for
  rich text, `render_slack()` for Slack. If your destination needs a fourth rule, add a fourth
  environment rather than widening an existing one; the split exists because a single global
  setting got one case wrong and shipped stored XSS. Assert **both halves** — escaped where it
  must be, untouched where it must not — so an over-broad fix fails as loudly as the bug.

**A parser:** a function in `parsers.py` plus a registry entry. Parsers must not raise on
malformed input — webhook payloads are documented optimistically and delivered otherwise, and a
parser that throws turns a cosmetic upstream change into a rejected delivery. Use defensive
lookups and return `actionable=False` when there is nothing to do.

## Tests

- The suite must pass and coverage must stay above 80%. Verification, redaction and the config
  guards are held at 100% — coverage is a floor, not the goal.
- **Name the scenario, not the function.** `test_forwarded_for_cannot_forge_the_peer`, not
  `test_verify_peer`.
- **Prove a security test is real.** Before trusting one, confirm it fails against the code
  *without* the guard. A test that passes either way documents nothing.
- Delivery tests drive `engine.run_once()` rather than waiting on the background loop. Set the
  poll interval past the life of the test so the loop cannot compete for the same rows — a short
  tick produces a suite that passes locally and fails on a slower runner.

### Fixtures are invented

Every value in `tests/` and `examples/` is made up. No real hostnames, room IDs, tokens or
internal addresses — this repo is public, and fixtures are the easiest place for something real
to slip in unnoticed. Use `example.invalid`, RFC 5737 documentation ranges (`192.0.2.0/24`,
`203.0.113.0/24`), and obviously-fake credentials.

`.gitleaks.toml` is the backstop, and it allowlists test values **by value, not by path** — a
blanket exemption for `tests/` would hide exactly the mistake it exists to catch.

## Pull requests

- Branch from `main`. CI must be green: lint, format, the 3.11/3.12/3.13 matrix, the wheel build,
  `pip-audit --strict`, and the image-contents check.
- Explain **why**, not just what. The diff shows what changed.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Commit subjects in the imperative mood, under 72 characters.
- All GitHub Actions pinned to commit SHAs, never floating tags.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md). Please don't open a public issue for one.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
