---
name: Bug report
about: Something behaves differently from how it is documented
labels: bug
---

<!--
Found a way to make the router ACCEPT a request it should have rejected, or a credential
reaching a log or the database? That is a vulnerability, not a bug — please report it privately:
https://github.com/TadMSTR/webhook-doorman/security/advisories/new
-->

## What happened

## What you expected

## Reproduction

**Your `config.yml`** — redact your secrets, but keep the structure. The `verify` and `dedup`
blocks are usually where the answer is.

```yaml

```

**How the request was sent** (`curl`, or the producer and event type):

```

```

## Relevant log lines

Logs are JSON on stdout. `LOG_LEVEL=DEBUG` gives more. Redact anything sensitive.

```json

```

## Environment

- webhook-doorman version / image tag:
- How you run it (Docker, compose, pip):
- `GET /health` output (it reports which sources are enabled and why any are not):
