# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-09-07

Supply-chain release. **No behavioural change to the service** — an existing 0.4.0 config runs
identically. What changed is what the project can prove about the image it publishes.

### The dependency tree that ships is now pinned and audited

`Dockerfile` ran `pip install '.[otel]'`: a fresh resolve at image-build time. The CI audit job
separately extracted the declared version *ranges* and ran `pip-audit -r` on them, which
re-resolves again. Those were two different resolutions at two different moments, and neither
was the tree in the published image — so the multi-arch image on GHCR had a dependency set that
nothing had audited.

- `uv.lock` is committed and is the source of truth. The image installs from it with
  `--require-hashes --no-deps`, so the build resolves nothing.
- The audit reads the lock through an exported PEP 751 `pylock.toml` with `pip-audit --locked`,
  which also resolves nothing. `-r` is not an alternative: it runs a pip dry-run resolution even
  with `--no-deps`.
- Split into **runtime** and **dev** gates. Dev dependencies were previously unaudited entirely.
- Declared ranges are bounded (`>=x,<next-major`) rather than bare floors.
- Dependabot maintains the lock, on the `uv` ecosystem — `pip` would update `pyproject.toml`
  and leave `uv.lock` frozen.

No vulnerabilities were found in the 0.4.0 image while making this change; the gap was that
nothing was looking.

### The published image is verified before it is pushed

`publish.yml` built and pushed in a single step, so nothing tested the artefact until after it
was public. It now builds amd64, verifies it, then pushes multi-arch. The arm64 leg is built
from the same Dockerfile and lock but is not itself smoke-tested — noted in the workflow rather
than left to assumption.

CI and the publish path now run the *same* script, `.github/ci/verify-image.sh`, so a gate
cannot apply to one path and silently not the other.

### CI asserts the service contract, not liveness

The image job checked contents, runtime uid and `--version`. It never asserted what the service
does. It now asserts, against the running container: an unsigned request is refused, a wrongly
signed request is refused, and **a correctly signed request is accepted**. The accept case is
the load-bearing one — without it a build whose verification rejected everything would pass
identically to one that works.

### Also

- Build provenance attestation on the published image.
- CodeQL (`python` and `actions`), OSSF Scorecard, `CODEOWNERS`, `dependabot.yml`.
- `packages: write` moved from workflow level to the single job that pushes.
- Coverage floor 80 → 95, with the measured figure (96.95%, 669 tests) and date recorded beside
  it; the flat 80 permitted a silent seventeen-point regression.
- `webhook-doorman --check` runs over every shipped example in CI, through the installed wheel.
- `docs/` is now a navigable set with an `index.md`; the configuration reference and the
  security model moved out of a 451-line README into `docs/configuration.md` and
  `docs/security.md`.

## [0.4.0] — 2026-08-30

A content-safety layer for destinations that feed an LLM agent, and the schema migration path
this project never had.

Everything in the safety layer is **opt-in**. `agent_readable` defaults false, `detector.backend`
defaults `none`, `filter` is empty, and `trust` defaults to `untrusted` — which is safe to
default precisely because it does nothing until a sink opts in. An existing 0.3.0 config renders
byte-identically on 0.4.0.

### Migration

**This release contains the first schema migration in the project's history, and it is applied
automatically on first start.** Read this section before upgrading.

`SqliteStore.connect()` had no migration path. It ran `CREATE TABLE IF NOT EXISTS` and then wrote
`PRAGMA user_version` without ever reading it — so on an existing database a new column was never
created *and* the version was bumped anyway. Any database written by 0.1.0 through 0.3.0 reports
a version it does not necessarily have.

0.4.0 replaces that with a real migrator:

- The version is **read** first, and a database with an `events` table but a zero `user_version`
  is treated as version 1 rather than as fresh. Structure decides, because the version field
  written by earlier releases cannot be trusted.
- Each migration runs in its own transaction with the `user_version` write inside it. SQLite
  journals the pragma with the DDL, so a crash mid-upgrade rolls both back and the next start
  re-runs that step cleanly.
- **A database whose version is newer than the running build now refuses to open**, raising
  `StoreError`. Rolling back from 0.4.0 to 0.3.0 will therefore fail to start rather than writing
  0.3.0 statements to a 0.4.0 file. That is deliberate: a downgrade that writes is silent
  corruption. Restore a backup taken before the upgrade, or stay on 0.4.0.

Three nullable/defaulted columns are added to `events`. Existing rows are preserved and read
back with sane defaults; no data is rewritten. **Take a copy of your database file before
upgrading**, as you would for any first-of-its-kind migration.

### Added

- **Structural event filtering.** `filter.event_types` allowlists against the parser's
  `event_type`; `filter.require` and `filter.deny` match dotted paths into the *decoded payload*,
  so they work under `parser: generic` too. A path that does not resolve **fails** a `require`
  and **passes** a `deny` — the asymmetry is what makes both usable. `deny` is evaluated first.
  A filtered event is stored with status `filtered` and zero deliveries, and answered **200**:
  a non-2xx makes a well-behaved producer retry harder over a decision that will not change.
- **`filter.max_field_bytes`**, a per-string-field byte cap on the stored summary and parser
  context, cut on a UTF-8 character boundary. Deliberately not applied to `payload`, which is
  re-derived from the stored body on every read.
- **Source `trust` and sink `agent_readable`.** Together they fence attacker-authored fields in
  rendered output as `<untrusted source="..." field="...">`. Structural fields — `source`,
  `event_type`, `delivery_id`, `event_id`, and parser-derived values like `repo` — stay outside
  the fence. Forged fence tags in content — opening or closing, with or without attributes — are
  removed before wrapping, and `detect.py`'s `fence_forgery` rule scores the same shape so an
  attempt is still recorded after it has been neutralised.
- **`{{ event_id }}`** in the template context, as a stable idempotency key for a downstream
  agent.
- **Unicode sanitization** on any `untrusted` source, regardless of destination: the tag block
  `U+E0000-U+E007F`, bidi overrides, zero-width characters, and C0/C1 controls other than tab,
  newline and return are removed, and the text is NFKC-normalised.
- **A pluggable detector interface** with a dependency-free heuristic backend. `score()` returns
  `None` for "could not evaluate", which is surfaced as `verdict="unavailable"` and **never**
  conflated with `clean`. `on_error` has no `drop` member — discarding an event because the
  detector failed is not something the config language can express.
- **`GET /admin/held`** and **`POST /admin/release/{event_id}`**, behind the existing admin
  bearer token. `/admin/held` returns failure metadata only, on the same rule as `/admin/dlq`.
  Releasing an already-released event is a no-op, not a second enqueue.
- **`/health` gains a `detector` block** (`configured`, `backend`, `available`, `last_error`). A
  degraded detector stays **200** — a router whose detector is down still routes, and the
  documented 503 conditions are unchanged.
- **Five new metric series**, all with bounded label cardinality:
  `webhook_doorman_events_filtered_total{source,reason}`,
  `webhook_doorman_content_sanitized_total{source,class}`,
  `webhook_doorman_detection_total{source,verdict}`,
  `webhook_doorman_detection_latency_seconds{backend}`,
  `webhook_doorman_events_quarantined_total{source,rule}`, and the
  `webhook_doorman_held_events` **gauge**. Nothing producer-controlled is ever a label — a
  detector reports rule *names*, never matched text.
- **`examples/github-to-agent.yml`**, a worked agent-facing configuration.

### Changed

- `EventStatus` gains `filtered`, `quarantined` and `dropped`. `quarantined` is releasable;
  `dropped` deliberately is not, which is the whole difference between them.
- `Store` gains `record_detection`, `release_event` and `list_held`. `store.stats()` gains
  `events_quarantined`.
- `Metrics.observe()` generalises the histogram machinery to more than one family.
  `Metrics.initialise()` gains optional `untrusted_sources` and `detector_enabled` arguments, so
  series are only created where they can be non-zero.
- `Engine.replay` and the new `Engine.release` share sink resolution, so they cannot disagree
  after a config change.

### Fixed

- **`SqliteStore` applies schema migrations.** See the Migration section above.
  `SCHEMA_VERSION` is now derived from the migration table rather than declared beside it, so
  the two cannot drift — which was the defect the migrator was added to fix.
- `store/base.py` documented a migration contract that nothing implemented, for three releases.
  The docstring and the implementation now agree.

### Security

- No new runtime dependencies. The image is unchanged in size.
- `SECURITY.md` gains a section stating the boundary plainly: the detector is defence in depth
  and is evadable, and a detector miss is expected rather than a vulnerability. The fence being
  escapable *is* a vulnerability, and is now a listed design commitment.

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
- **Sink credentials would have been exported on trace spans.** Enabling tracing also enables
  OTel's automatic `httpx` instrumentation, which records the full request URL on every client
  span — and for Discord and Slack the webhook URL *is* the credential, while for Apprise it is
  the `key` path segment. Resolved secrets are now scrubbed from span attributes before export,
  matching by value rather than by attribute name so the guard survives OTel's in-progress
  `http.url` → `url.full` rename. Found in the pre-release audit; never shipped.

  Note the limit: this covers credentials declared through a `*_env` field, which is how every
  bundled sink declares one. A `type: http` sink with an authenticated URL written inline as
  `url:` is not a resolved secret and is redacted nowhere — use `url_env`.

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

[0.5.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.5.0
[0.4.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.4.0
[0.3.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.3.0
[0.2.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.2.0
[0.1.1]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.1.1
[0.1.0]: https://github.com/TadMSTR/webhook-doorman/releases/tag/v0.1.0
