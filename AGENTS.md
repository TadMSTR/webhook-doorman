# AGENTS.md — operating contract for webhook-doorman

Read this before changing anything in `src/`. It records the invariants that are easy to break
without noticing and hard to detect once broken.

## What this project is

A fail-closed inbound webhook router. It accepts webhooks from many producers on one ingress,
verifies each against a per-source strategy declared in YAML, persists the event, and delivers it
to configured sinks with retry and a dead-letter queue.

The product is **pluggable per-source fail-closed verification**. Everything else — persistence,
retry, templating — is supporting infrastructure. When a change trades verification strictness
for convenience, the change is wrong.

## Module boundaries

| Module | Owns | Must not |
|---|---|---|
| `config.py` | Parsing and validating `config.yml` into pydantic models | Read the environment, touch I/O, know about HTTP |
| `secrets.py` | Binding a config to the environment; enabled/disabled state | Decide whether a request is valid |
| `verification.py` | Deciding whether a request is authentic | Import FastAPI, log, or read config files |
| `redaction.py` | Removing credentials before persistence or logging | Know about sources, sinks or storage |
| `parsers.py` | Turning a vendor payload into template variables | Decide routing, or raise on a malformed payload |
| `app.py` | HTTP: routes, body limits, status codes | Contain verification logic, or persist anything |
| `store/` | All SQL. The `Store` protocol and its SQLite implementation | Know about HTTP or sinks |
| `sinks/` | Outbound delivery to one destination type | Know which source produced an event |
| `engine.py` | Persist-then-dispatch, retry scheduling, DLQ, sweeps | Contain SQL, or verification logic |

**No sink knows its source.** A sink that special-cases `if source == "github"` has broken the
abstraction the whole design rests on. Routing is config.

## Invariants

Each of these has an explicit negative test. Removing the test is removing the invariant.

1. **Verification is over raw bytes, before JSON decoding.** Never re-serialise and compare.
2. **Every credential comparison uses `hmac.compare_digest`.** No `==` on a secret, ever.
3. **An unset secret disables the source and rejects.** There is no "verification skipped" path.
   `verification.py`'s functions also return False for an empty secret, so a misordered call
   still fails closed.
4. **`strategy: none` requires all three guards** — `server.allow_unverified`, a per-source
   `unverified_reason`, and a non-empty `allow_from`. Enforced at startup, in code.
5. **`allow_from` matches the socket peer.** Never `X-Forwarded-For`, never `X-Real-IP`. The
   packaged entry point runs uvicorn with `proxy_headers=False` to keep this true.
6. **Credentials are redacted before the event object is constructed.** Not before the write —
   before the object exists, so there is no window in which an un-redacted event could be handed
   to the store by mistake.
7. **A duplicate delivery returns 200 with `deduplicated: true`.** Never 4xx. GitHub marks a
   non-2xx delivery failed and retries harder; answering a retry with an error makes it worse.
8. **A verification failure returns 401 with no detail.** The reason goes to the log. Telling a
   caller which check failed helps an attacker more than a developer.
9. **Structural config errors are startup failures.** Never deferred to the first request.
10. **The bind address is not configurable.** See "Exposure model" in ARCHITECTURE.md.

## Adding things

**A source:** a `config.yml` entry. No code. If you find yourself editing Python to add a
producer, the abstraction has a gap — fix the gap, not the symptom.

**A verification strategy:** a model in `config.py` added to the `VerifySpec` union, a function in
`verification.py`, a branch in `verify()`, and negative tests for empty secret, missing header
and wrong credential. The `verify()` fallthrough must stay `False`.

**A sink:** a model in `config.py` added to the `SinkSpec` union, a class in `sinks/`
implementing `Sink`, and registration in `sinks/__init__.py`. Raise `PermanentSinkError` for
failures a retry cannot fix, `SinkError` for ones it can.

**A parser:** a function in `parsers.py` plus a registry entry. Parsers never raise on malformed
input — a cosmetic upstream change must not become a rejected delivery.

## Testing

- `pytest` with an 80% floor in CI; verification, redaction and the config guards are held at
  100%. Coverage is a floor, not a goal — the negative tests are the coverage that matters.
- Test names describe the scenario: `test_forwarded_for_cannot_forge_the_peer`, not
  `test_verify_peer`.
- **Fixtures are invented.** No real hostnames, room IDs, tokens or internal addresses anywhere
  in `tests/` or `examples/`. This repo is public and fixtures are where topology leaks in.
- Prove a security test is real: confirm it fails against the code without the guard before
  trusting it.

## Public repo rules

- No deployment topology in this repo — not addresses, not hostnames, not room IDs. `examples/`
  uses invented values and RFC 5737 / RFC 2606 ranges.
- The published image is public. `.dockerignore` must keep `.env`, `config.yml` and `tests/` out
  of the final layer; verify with `docker history` before tagging.
- All GitHub Actions are pinned to commit SHAs, never floating tags.
