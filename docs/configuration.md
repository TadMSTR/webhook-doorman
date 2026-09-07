# Configuration

Every option webhook-doorman reads, and the reasoning behind the ones that are easy to get
wrong. Worked configurations live in [`examples/`](../examples/); each of them is parsed by
`--check` in CI on every pull request, so anything here that stopped working would fail a build
rather than sit in the docs.

Validate a config before deploying it:

```bash
webhook-doorman --config config.yml --check
```

## Configuration

Two layers, and the split is the point:

- **`config.yml`** — topology. Which sources exist, how each is verified, where events go.
  Non-secret, safe to commit.
- **The environment** — secrets. YAML names the variable; the value never appears in the file.
  There is no inline form of any credential field.

```yaml
sources:
  - name: github
    path: /webhook/github
    verify:
      strategy: hmac_sha256
      header: X-Hub-Signature-256
      prefix: "sha256="
      encoding: hex
      secret_env: GITHUB_WEBHOOK_SECRET   # a name, never a value
    dedup:
      id_header: X-GitHub-Delivery
    parser: github
    sinks: [team-chat]

sinks:
  - name: team-chat
    type: matrix
    url_env: MATRIX_HOMESERVER
    token_env: MATRIX_TOKEN
    room_env: MATRIX_ROOM
    template: "{{ summary }}"
```

See [`config.example.yml`](../config.example.yml) for a fully commented file and
[`examples/`](../examples/) for worked configurations.

### Sinks

| Type | Credential | Notes |
|---|---|---|
| `matrix` | `token_env`, `room_env` | `url`/`url_env` is the homeserver base |
| `ntfy` | `topic_env`, optional `token_env` | non-ASCII titles are RFC 2047 encoded |
| `vikunja_task` | `token_env` | `description` is HTML-escaped; `title` is not |
| `http` | optional `token_env` | the escape hatch — any endpoint that speaks JSON |
| `discord` | **`webhook_url_env`** | mentions disabled on every message; 2000-char truncation |
| `slack` | **`webhook_url_env`** | `&<>` escaped in interpolated values |
| `apprise` | `key_env` | `url`/`url_env` is the apprise-api base; 204 and 424 dead-letter; escaping follows `body_format` |

Discord and Slack take `webhook_url_env` rather than `url`/`url_env`, and have no inline form:
their webhook URL embeds its own token, so the URL *is* the credential and belongs in the
environment with the rest of them.

Escaping is per-sink and not configurable, because it is a property of the destination rather
than of the data — Discord disables mention resolution, Slack escapes `&`, `<` and `>`, Vikunja
escapes its HTML description field, and the chat sinks escape nothing. Webhook content is
attacker-authored on any public repo; a flag that defaults safe still lets someone switch it off
without knowing what it was for.

It follows the *renderer*, not the format. Discord's content is Markdown and is left unescaped
because Discord does not render raw HTML; Apprise's `body_format: markdown` is escaped because
apprise-api converts it through an unsanitised Markdown-to-HTML step. Same format, opposite
rule. `ARCHITECTURE.md` has the reasoning.

### Verification strategies

| Strategy | Fields | Typical producer |
|---|---|---|
| `hmac_sha256` | `header`, `secret_env`, `prefix`, `encoding` | GitHub, GitLab, Vikunja, most vendors |
| `bearer` | `secret_env`, `header`, `prefix` | Grafana, internal producers |
| `basic` | `user_env`, `pass_env`, `header` | Grafana's other option |
| `none` | `unverified_reason`, `allow_from` | Loopback-only internal producers |

### `none` is guarded, not free

`strategy: none` accepts a request on reachability alone, so it takes three things to enable and
the server **refuses to start** without all of them:

1. Top-level `server.allow_unverified: true`.
2. A per-source `unverified_reason` — write down why, for the next person.
3. A non-empty `allow_from` CIDR list. There is no allow-all form; an omitted or empty list is a
   startup error.

`allow_from` matches the **socket peer address**, never `X-Forwarded-For` — an allowlist a caller
can bypass by setting a header is not an allowlist. Run behind a proxy and you want a real
strategy instead.

---

See also: [security.md](security.md) for the exposure model and the content-safety layer,
[deployment.md](deployment.md) for file permissions and reverse-proxy setup.
