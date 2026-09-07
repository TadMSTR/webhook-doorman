# Security Audit

Every release branch of this project is audited by an independent reviewer before it merges.
This page is the record: what was examined, what was found, and what was done about it.

## Audit History

| Date | Version / Scope | Findings | Status |
|------|-----------------|----------|--------|
| 2026-08-20 | v0.1.1 — fail-closed correctness (PR #2) | 0 critical / 0 high / 0 medium / 0 low | Clean |
| 2026-08-20 | v0.1.1 → v0.2.0 — Discord/Slack/Apprise sinks (PR #3) | 0 critical / 0 high / 1 medium / 1 low | Remediated before merge |
| 2026-08-20 | v0.3.0 — observability (PR #4) | 0 critical / **1 high** / 0 medium / 0 low | Remediated before merge |
| 2026-08-30 | v0.4.0 — agent content-safety layer (PR #5) | 0 critical / 0 high / 0 medium / 0 low (2 informational) | Clean |
| 2026-09-07 | v0.4.0 → v0.5.0 — supply chain (PR #6) | 0 critical / 0 high / 1 medium / 0 low | Remediated before merge |

## Summary

Five audits. One High finding across the project's history, remediated before it shipped.

The High was in the v0.3.0 observability build: OpenTelemetry's automatic `httpx`
instrumentation, enabled whenever tracing was turned on, exported the full destination URL as a
span attribute — and sink URLs can carry embedded credentials. A tracing feature was therefore
capable of exporting the secrets the redaction layer exists to contain. Fixed before merge.

The recurring theme across the sink audits was **escaping belongs to the destination**: the
Apprise sink's `body_format: "markdown"` path was treated as plain text rather than as a
rich-text rendering context. That lesson is now written into `ARCHITECTURE.md` as a design
decision rather than living only in an audit report.

The v0.5.0 supply-chain audit found one Medium, described below, and is the reason this project
can now say something specific about the image it publishes rather than something general.

## Findings and Remediation

### 2026-09-07 audit — v0.5.0 supply chain (PR #6)

Scope: dependency pinning and audit, the publish path, the HTTP service-contract smoke test,
and the new CodeQL / Scorecard / CODEOWNERS / Dependabot configuration.

**[MEDIUM] Base images pinned by tag only, not by digest.** Both `FROM python:3.13-slim`
stages carried a floating tag while the `uv` build stage three lines below was pinned by tag
*and* digest — with a comment reading *"a mutable tag in a build stage is an unpinned dependency
wearing a version number."* The file stated the rule and then broke it twice.

Two things made this worth a Medium rather than a nit. Dependabot does not close it while
tag-pinned: its `docker` ecosystem opens a PR when the version tag moves (`3.13` → `3.14`), not
when the registry repoints content behind an unchanged tag. And the image gates described below
audit Python packages from installed metadata, so an OS base-layer change is invisible to them.

Fixed before merge (`f417cfa`): both stages pinned to a digest. The digest was verified to be a
multi-arch OCI image index before it was applied — `publish.yml` builds `linux/arm64` as well,
and a single-platform digest would have broken that leg at publish time. The rebuilt image ID
was byte-identical to the pre-pin build, so the pin records what was already being pulled.

**Reviewed and cleared, no finding filed.** A synthetic HMAC secret is committed in
`.github/ci/verify-image.sh`; it signs one request to a loopback-only throwaway container that
is destroyed in the same script run, and the accept assertion cannot exist without it. The
arm64 image is published without its own smoke test — deliberate, documented inline, and
disclosed rather than hidden; amd64 is verified from the identical Dockerfile and lockfile
before either architecture is pushed.

### 2026-08-30 audit — v0.4.0 agent content-safety layer (PR #5)

No Critical, High, or Medium findings. Two informational items. The reviewer noted that every
residual risk the build claimed was already documented in `SECURITY.md` — specifically that the
content-safety layer is defence in depth and is evadable, which the project says about itself
rather than leaving a reader to discover.

### 2026-08-20 audits — v0.1.1 through v0.3.0 (PRs #2, #3, #4)

- **PR #2, fail-closed correctness** — clean. Sink credential discovery, `/health` honesty,
  sink error handling.
- **PR #3, Discord/Slack/Apprise sinks** — one Medium (`body_format: "markdown"` rendered
  unescaped into a rich-text context) and one Low (a redaction claim in the build request was
  not backed by a test). Both fixed before merge; the Low is the reason redaction now has
  explicit test coverage rather than an assertion in a commit message.
- **PR #4, observability** — the one High in the project's history, described in the Summary
  above.

## What the audits verify, and what they cannot

The v0.5.0 audit reproduced every supply-chain claim directly rather than reading the pull
request's description of it: both dependency-audit gates, a real image build, all five gates in
`.github/ci/verify-image.sh` run end to end against that image, the test suite and its coverage
figure checked against the number recorded in `pyproject.toml`, a secret scan over the commit
range, and three of the pinned GitHub Actions re-fetched from GitHub to confirm each SHA matches
its version comment. It also checked something the request had not claimed — that HMAC
comparison uses `hmac.compare_digest`.

Two limits are worth stating plainly, because a green audit is easy to over-read:

- **A CVE-database check is not a trust review.** `pip-audit` reports known advisories against
  the 79 locked packages. It cannot detect an undisclosed or novel compromise of a package
  itself.
- **The arm64 image is not exercised.** Neither by CI nor by the audit. It is built from the
  same Dockerfile and the same lockfile as the verified amd64 image, and that is the whole of
  the assurance.

## Reporting

To report a vulnerability, see [SECURITY.md](../SECURITY.md). Full audit reports are held in
the `host-forge/build-reports` repository, one directory per build.
