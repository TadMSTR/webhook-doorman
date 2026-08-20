# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Declarative configuration (`config.yml`): sources, sinks and routing as data. Secrets are
  referenced by environment variable name and have no inline form.
- Verification strategies: `hmac_sha256` (hex or base64, configurable header and prefix),
  `bearer`, `basic`, and a guarded `none`.
- Startup guard for `strategy: none` — requires `server.allow_unverified`, a per-source
  `unverified_reason`, and a non-empty `allow_from` CIDR list. Matched against the socket peer,
  never a forwarded-for header.
- Per-source enabled state: an unset secret disables that source and rejects with 503 rather
  than skipping verification.
- Credential redaction before persistence, by header name and by secret value, over both
  headers and body.
- `/health` reporting per-source and per-sink state, named unverified sources, and whether the
  replay endpoint is enabled.
- Request body cap enforced from the declared `Content-Length` and again while streaming.
- Durable delivery on SQLite in WAL mode: event log, dedup on `(source, delivery_id)`, retry
  with jittered exponential backoff, a dead-letter queue, and a retention sweep.
- Re-queue of any `pending`/`in_flight` delivery at startup, so a process killed mid-delivery
  resumes rather than stranding the event.
- A duplicate delivery is answered `200` with `deduplicated: true`. Never `4xx` — a producer
  reads a non-2xx as failure and retries harder.
- `POST /admin/replay/{event_id}`, authenticated with a bearer token of at least 32 characters
  and disabled entirely without one.
- Sinks: `matrix`, `ntfy`, `vikunja_task` and a generic `http`, each rendering a Jinja2 template
  in a sandboxed, text-only environment. Sinks are independent of sources.
- Retryable and permanent sink failures are distinguished: 5xx, 408, 429 and transport errors
  back off; other 4xx and template errors go straight to the DLQ.

- Multi-stage Dockerfile on `python:3.13-slim`, running as a fixed non-root UID 10001, with a
  stdlib `HEALTHCHECK` on `/health` and `/data` as a volume.
- Multi-arch publish (amd64 + arm64) to `ghcr.io/tadmstr/webhook-doorman` on push to `main` and
  on tags, using the workflow's built-in `GITHUB_TOKEN` — no PAT, no repository secret.
- `docker-compose.yml` with hardened defaults: `read_only`, `no-new-privileges`, `cap_drop: ALL`,
  and a loopback-only publish.
- CI job that builds the image and asserts on its actual filesystem that no `.env`, `config.yml`
  or test fixture reached the published layers, and that the runtime UID is not root.
- Parsers for `vikunja` and `grafana` alongside `github` and `generic`.
- `ARCHITECTURE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/deployment.md`, Mermaid
  diagrams for verification enforcement and the delivery lifecycle, three worked examples,
  `.pre-commit-config.yaml`, and issue and PR templates.
- Tests that every shipped example config loads, contains no inline credential, and contains no
  real hostname, address or room ID — the public-repo guard runs on every PR rather than at
  review time, because a leaked value stays in the git history whatever the next commit does.

### Fixed

- A secret echoed into a payload field could reach the event log through a parser's `context`,
  which was persisted without redaction while the body it came from was redacted. Redaction now
  happens once at the ingest boundary and everything downstream — `payload`, `summary`,
  `context`, the dedup id — is derived from the redacted bytes. Caught by a test that reads the
  SQLite file and its WAL sidecar as raw bytes.
- `dedup.id_header` naming a credential header is now a startup error. It would have been
  redacted before storage, collapsing every event onto one dedup id and silently discarding all
  but the first.
