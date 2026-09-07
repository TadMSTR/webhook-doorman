# webhook-doorman documentation

A fail-closed webhook router: it verifies a delivery before anything else touches it, then
parses, redacts, stores and fans it out to configured sinks.

Start with the [README](../README.md) for what the project is and a quickstart. This index is
the map of everything below it.

## Guides

| Document | Read it when |
|---|---|
| [configuration.md](configuration.md) | Writing or changing a `config.yml` — sources, sinks, verification strategies |
| [deployment.md](deployment.md) | Running it: exposure, file permissions, reverse proxy, migrating from an existing receiver |
| [security.md](security.md) | Deciding what to point at it, or what it protects you from |
| [security-audit.md](security-audit.md) | What independent review has found, and what was done about it |

## Reference

| Document | Contents |
|---|---|
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | Design decisions and their reasoning; extension points |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability; threat-model boundaries |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Adding a source, sink or strategy; code style; tests |
| [../examples/](../examples/) | Worked configs, all parsed by CI on every pull request |

## Diagrams

| Diagram | Shows |
|---|---|
| [verification-enforcement.mmd](verification-enforcement.mmd) | Every path from a request to admitted or refused |
| [delivery-lifecycle.mmd](delivery-lifecycle.mmd) | Delivery states, retry, DLQ, crash recovery |

## How the docs are kept honest

The examples are not illustrative text — CI runs `webhook-doorman --check` over every file in
[`../examples/`](../examples/) on every pull request, and asserts it found at least five of
them. A config router whose own published examples do not parse is the worst failure available
to it, so that gate exists rather than a promise to keep them current.
