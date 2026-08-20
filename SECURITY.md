# Security Policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/TadMSTR/webhook-doorman/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include what you did, what happened, and what you expected. A minimal `config.yml` that
reproduces the behaviour is the single most useful thing you can attach — redact your secrets.

Expect an acknowledgement within 7 days. This is a personal project, so timelines are
best-effort, but a report that shows a verification bypass will be treated as urgent.

## Supported versions

The latest released version. There are no maintained backport branches.

## What is in scope

- Any path that accepts a request it should have rejected — a signature bypass, a `none` source
  reachable from outside its `allow_from`, a disabled source that still serves.
- Credential exposure: a secret reaching the event log, a log line, an error response, or the
  published image.
- Anything that lets a caller reach `/admin/` without a valid token.
- **`GET /admin/dlq` returning anything beyond failure metadata.** It reports `event_id`,
  `source`, `sink`, `attempt`, `response_code`, `error` and `exhausted_at`. It must never return
  a stored payload, request headers, or parser context — the event body is retrievable only by
  deliberately replaying it, and a list endpoint over stored bodies would be a much larger
  exfiltration surface behind the same single token. A response containing payload content is a
  vulnerability.
- **A secret reaching `/metrics`.** The endpoint exposes source and sink *names* and traffic
  volume; anything else in its output — a payload fragment, a header, a credential — is a bug.
- Template sandbox escape: reaching the filesystem, the environment, or arbitrary code execution
  through a sink template.
- Webhook content reaching a bundled sink's destination without escaping appropriate to how that
  destination renders it — for example unescaped HTML reaching a rich-text field.
- Denial of service through unbounded resource use — an unbounded body read, unbounded storage
  growth, a retry loop that never terminates.

## What is out of scope

- **Reverse proxy and TLS configuration.** This service speaks plain HTTP and expects a proxy in
  front of it for public ingress.
- **The exposure decision itself.** The container binds `0.0.0.0` by design; what can reach that
  port is the operator's port-publish and network configuration. See ARCHITECTURE.md.
- **`/metrics` being unauthenticated by default.** That is deliberate — it is the Prometheus
  scrape convention, and a mandatory token breaks a stock `scrape_config`. It exposes topology,
  never a credential. Deny it at the reverse proxy alongside `/admin/`, or set
  `metrics.token_env` if you accept the non-standard scrape config. Note that a token shorter
  than `metrics.min_token_length` is treated as absent and leaves the endpoint open; that is
  logged as `metrics_unauthenticated` at every boot.
- **`strategy: none` used carelessly.** It is guarded and it warns loudly, but an operator who
  sets `allow_from: ["0.0.0.0/0"]` has made an informed choice.
- **The secrecy of your secrets.** A leaked webhook secret lets an attacker forge signed
  requests; that is verification working, not failing.
- Vulnerabilities in producers, sinks, or upstream dependencies — report those upstream, though
  a note here is welcome if this project's use of them makes an issue worse.

## Design commitments

These are the properties this project is built to hold. A report showing any of them broken is a
vulnerability, not a feature request.

1. There is no code path where a missing or empty secret results in a request being accepted.
2. Every credential comparison is constant-time.
3. HMAC is computed over the raw request bytes, before any decoding.
4. Credentials are redacted before anything is written to storage or a log. **That includes a
   destination's own response body**, which reaches the DLQ inside a delivery error message —
   redacted at the engine boundary since 0.3.0.
5. A verification failure tells the caller nothing about why.
6. A bundled sink escapes webhook content for the way its destination renders it. Verification
   proves a payload's *origin*, never that its *content* is safe — an issue title on a public
   repo is written by a stranger and is authentically signed by GitHub either way.

## Escaping in your own templates

The bundled sinks handle this: the Vikunja sink escapes its description, because Vikunja renders
that field as HTML, and the chat sinks do not, because escaping a chat message corrupts it.

A `type: http` sink is yours. If you point one at something that renders HTML, escape explicitly
with Jinja's `| e` filter — the generic sink cannot know how your endpoint treats its input.
For JSON bodies use `| tojson`, which is the correct escaping for that context.
