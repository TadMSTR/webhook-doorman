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
