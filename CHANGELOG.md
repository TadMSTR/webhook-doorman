# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-08-20

Observability. The logging half of this project was always good — structured JSON, stable event
names — but there was no numeric telemetry at all, and the dead-letter queue was write-only: the
repo shipped a replay endpoint with no way to discover what to replay.

**Read the Changed section before upgrading.** A 3xx response is no longer counted as a
successful delivery, which is a behaviour change for every sink.

### Added

- **`GET /admin/dlq`.** Lists dead-lettered deliveries, newest first, behind the same bearer
  token as replay and checked before any database read. This is how you find the `event_id` for
  `POST /admin/replay/{event_id}`. Returns **failure metadata only** — `event_id`, `source`,
  `sink`, `attempt`, `response_code`, `error`, `exhausted_at` — and never the payload; the event
  body stays retrievable only by deliberately replaying it. Keyset pagination on `id` rather
  than `OFFSET`, because the retention sweep deletes rows underneath a paging client and
  `OFFSET` silently skips one for every deletion behind the cursor. `limit` is clamped
  server-side at 100.
- **`GET /metrics`.** Prometheus text exposition, emitted directly — **no `prometheus_client`
  dependency**; the default install stays at nine. Counters for events received, deduplicated,
  verification failures, pre-verification rejections and delivery attempts by outcome; gauges
  for the current events, deliveries-by-status and DLQ counts; `build_info` and
  `process_start_time_seconds`. Every config-derived series is initialised at zero, so "no
  failures yet" is distinguishable from "target not reporting".

  The gauges are point-in-time and deliberately **not** named `_total` — they go down when the
  retention sweep runs, and a counter that goes down is a reset to Prometheus. No label is
  producer-controlled: `event_type` and `response_code` are unbounded and stay in the log line.

  Unauthenticated by default, which is the scrape convention — a mandatory token breaks a stock
  `scrape_config`. It exposes source and sink names and traffic volume, never a payload or a
  secret. Deny it at the reverse proxy alongside `/admin/`, or set `metrics.token_env`.
- **`webhook_doorman_delivery_latency_seconds`**, a histogram with fixed buckets, labelled by
  sink. Observed on **every settled attempt including failures** — a destination that is slow
  *and* failing is the case you most want to see, and a histogram fed only by successes improves
  its own p99 as the destination gets worse. Timeouts and transport errors carry their real
  elapsed time rather than zero.
- **Optional OpenTelemetry**, behind a `[otel]` extra and off unless
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set. One span per ingest and one per delivery attempt,
  correlated by `delivery_id` rather than parented — a retry runs in the background worker
  minutes after its request finished. Spans carry only config-derived and structural attributes;
  no payload content, headers or rendered template output. The published Docker image includes
  the extra, so enabling tracing there is one environment variable.
- **`metrics.token_env`** and **`metrics.min_token_length`** config keys.

### Changed

- **A `3xx` response is now a permanent failure, not a successful delivery.** The engine sets
  `follow_redirects=False` on purpose — a Discord or Slack webhook URL embeds its own credential,
  and following an attacker-influenced `Location` would hand it over — so an un-followed redirect
  delivers nothing. It was being recorded as a success: no retry, no DLQ row, nothing above
  debug. An operator who typed `http://` at an instance redirecting to `https://` had a sink
  reporting every delivery as successful while notifying nobody. The dead-letter reason names the
  `Location` header.

  **If your destination legitimately answers 3xx, it will now dead-letter.** Point the sink at
  the final URL. This is why 0.3.0 is a minor release.
- A source `path` may no longer start with `/metrics`, for the same reason it may not start with
  `/admin`: both are expected to be denied at the reverse proxy, and an ingest path under either
  would be silently blocked by that rule.
- The destination response body carried in a delivery error is truncated to 80 characters,
  down from 200.

### Fixed

- **Delivery error text reached the dead-letter queue unredacted.** Redaction runs at the ingest
  boundary, so it covers what a producer sent — it never covered what a *destination* sent back,
  and `HttpSinkBase._send` puts part of that response body into the error message that
  `mark_exhausted` persists verbatim. A destination echoing a submitted credential into its own
  `400` page wrote that credential into the DLQ, where it survived every backup of the SQLite
  file. Redaction now also runs at the engine boundary, on both store-writing paths and on the
  log line. Fixed **before** `GET /admin/dlq` shipped, so the column was never exposed over HTTP
  unredacted.

## [0.2.0] — 2026-08-20

Three new sinks. Discord and Slack were already reachable through `type: http`, and that was the
problem: it required hand-templating raw JSON, and `GenericHttpSink` dead-letters a body that
does not parse — so an issue title containing a quote or a newline was lost unless the operator
remembered `| tojson`. Apprise was not expressible at all.

Nothing existing changes behaviour. Upgrading is a version bump.

### Added

- **`discord` sink.** Posts to an incoming webhook. Sends `allowed_mentions: {"parse": []}` on
  every request, which is not configurable: message content is attacker-authored on any public
  repo, and without it an issue titled `@everyone pwned` mass-pings the server. Discord's own
  webhook documentation recommends exactly this for user-generated strings. Content is
  truncated to Discord's 2000-character limit with a trailing `…` — over the limit Discord
  answers `400`, which is permanent, so a long release-notes payload would otherwise be lost
  rather than shortened. Optional `username`, `avatar_url` and `thread_id`.
- **`slack` sink.** Posts to an incoming webhook, escaping `&`, `<` and `>` in interpolated
  values. Slack's `mrkdwn` reads `<http://evil|your bank>` as a link whose visible label the
  writer chose, and `<!channel>` as a broadcast; escaping the angle brackets neutralises both.
  Also not configurable. Markup written in the template itself still renders, so `*{{ source }}*`
  works as expected.
- **`apprise` sink.** Fans out through an apprise-api instance via the stateful
  `POST {base}/notify/{key}` endpoint, so downstream credentials stay in Apprise's store rather
  than in doorman's config and in every outbound request. Options: `notify_type`, `body_format`,
  `tag`.

  **Each `body_format` gets the escaping its renderer needs, and all three were checked rather
  than defaulted.** `html` is HTML-escaped. `markdown` has its angle brackets escaped, because
  apprise-api converts Markdown to HTML through an unsanitised Python-Markdown and standard
  Markdown passes raw HTML through by design — an unescaped `<script>` in an issue title would
  otherwise arrive intact at every destination the key fans out to. `text` is left alone,
  because apprise-api runs its own `escape_html` on that path and escaping twice would show
  entities to the reader. Note that Discord's Markdown content is *not* escaped, for the same
  reason inverted: its flavour does not render raw HTML.

  **Two response codes are reclassified, and this is the substance of the sink.** `204` means
  Apprise notified *nothing* — an unknown key, or a key with no valid URLs — and because it is
  below 400 the generic HTTP rule reads it as a successful delivery. A typo'd key would swallow
  every event with no retry, no DLQ row and nothing above debug in the log. It is now permanent.
  `424` ("at least one notification failed") is permanent too, deliberately: retrying re-notifies
  the destinations that already succeeded, so the DLQ row is the honest outcome.
- `render_slack()` and `render_markdown()` in `templating.py`, joining `render()` and
  `render_html()`. Both are implemented as Jinja's `finalize` hook rather than an autoescape
  policy, because autoescape is hardwired to `markupsafe.escape` and that rewrites more than
  either destination wants — `"` and `'` for Slack, which renders them literally.

  Two of the four environments now serve Markdown destinations that need opposite treatment
  (Discord unescaped, apprise-api escaped), which is the clearest available statement that
  escaping follows the renderer rather than the format.
- `HttpSinkBase._classify()`, an overridable hook returning a `Verdict`, for destinations whose
  status codes disagree with HTTP's. Also the right seam for a destination that reports failure
  in the body of a `200` — Slack's `chat.postMessage` Web API does, should token posting ever
  be added.
- `examples/github-to-discord.yml`, routing one GitHub source to Discord and Slack together.

### Notes for adopters

`discord` and `slack` take **`webhook_url_env`**, not `url` / `url_env`, and have no inline
form. Their webhook URL embeds its own token, so the URL *is* the credential: an inline field
would invite committing a live secret to `config.yml` and would keep the value out of the
redaction set. This depends on the `sink_secret_env_names()` fix released in 0.1.1 — on 0.1.0
these sinks would report `enabled: true` with the variable unset.

## [0.1.1] — 2026-08-20

A correctness pass. Four places where the documented behaviour and the shipped behaviour had
drifted apart, all of them in the fail-closed direction the project exists to guarantee.

### Changed

- **`/health` now returns `503` when the router cannot do its job**, with `"status": "degraded"`
  and a `degraded` list naming why. It previously returned `200` and `"status": "ok"`
  unconditionally, which meant the image's `HEALTHCHECK` could not fail for any reason short of
  the process dying. **This is the one change an existing adopter's monitoring could notice.**

  Degraded means *no source is enabled*, or *the store is unreachable*. A partially degraded
  router — one source disabled out of several — still returns `200`, because a disabled source
  is usually a deliberate operator state and flapping a container on it would be a worse answer
  than the silence it replaces. The disabled source is named in the body either way.
- `sink_secret_env_names()` derives a sink's credentials from the model instead of a hardcoded
  `("token_env", "room_env", "topic_env", "url_env")` tuple. Any `*_env` field is now found
  automatically. A sink with a credential field outside that tuple was reported `enabled: true`
  at `/health` with its variable unset, and its value never entered the redaction set — so it
  was never redacted from the stored event. No bundled sink was affected; every sink added from
  here on is.
- A retryable response carrying `Retry-After` now schedules the next attempt against the
  advertised delay instead of the exponential curve. Both RFC 9110 forms are accepted. The
  value is clamped to `delivery.max_backoff_seconds` and still jittered — an unclamped delay
  would let a destination park a delivery indefinitely without it ever reaching the DLQ.
- `/health` includes a `stats` block (event, delivery and DLQ counts) when an engine is
  attached. `stats()` was implemented at three layers and called from nowhere but tests.

### Fixed

- **The `ntfy` sink no longer fails on a non-ASCII title.** An em-dash, curly quote, accented
  name or emoji in the rendered `title_template` raised `UnicodeEncodeError` inside httpx,
  escaped the sink's error handling, and burned every retry on a failure that could never
  succeed. Titles are now RFC 2047 encoded-words (`=?UTF-8?B?…?=`) when — and only when — they
  contain non-ASCII, which ntfy documents and decodes.
- `HttpSinkBase` treats any `UnicodeError` as a permanent failure, so an unencodable request
  reaches the DLQ on the first attempt rather than after `max_attempts` of identical failures.

### Added

- `LOG_FORMAT=console` selects structlog's `ConsoleRenderer` for local development. The default
  stays `json`; anything unrecognised falls back to `json` rather than to a surprise.
- Request-scoped log context: every line emitted while handling a request carries `source`, and
  `delivery_id` once it is known. A `verification_failed` or `body_too_large` line previously
  carried a source name and nothing else, so a 401 could not be correlated with the request
  that caused it.

## [0.1.0] — 2026-08-20

First release. Security-audited before tagging: one Medium finding, resolved below.

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

### Security

- **Webhook content reaching a rich-text destination is now escaped.** The `vikunja_task` sink
  rendered its `description` — which Vikunja renders as HTML — with autoescape off, so a GitHub
  issue title or body from a public repo became stored XSS against whoever opened the task.
  Templating now has two environments: `render_html` (autoescape on) for destinations that
  render rich text, and `render` (autoescape off) for chat, push and JSON bodies, where escaping
  would corrupt the output. The Vikunja `title` remains unescaped — it is a plain-text field.
  Found by security audit `forge-webhook-router-2026-08` (Medium, the only finding).

### Fixed

- A secret echoed into a payload field could reach the event log through a parser's `context`,
  which was persisted without redaction while the body it came from was redacted. Redaction now
  happens once at the ingest boundary and everything downstream — `payload`, `summary`,
  `context`, the dedup id — is derived from the redacted bytes. Caught by a test that reads the
  SQLite file and its WAL sidecar as raw bytes.
- `dedup.id_header` naming a credential header is now a startup error. It would have been
  redacted before storage, collapsing every event onto one dedup id and silently discarding all
  but the first.

[0.3.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.3.0
[0.2.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.2.0
[0.1.1]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.1.1
[0.1.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.1.0
