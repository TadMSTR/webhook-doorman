# Security model

What webhook-doorman protects, what it does not, and the reasoning behind each control.

This is the *model*. Two neighbouring documents cover different questions and are not
duplicates of it:

| Document | Question it answers |
|---|---|
| [SECURITY.md](../SECURITY.md) | How do I report a vulnerability, and what is in scope? |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Why is the code shaped this way? |
| [deployment.md](deployment.md) | How do I run it without opening a hole? |

The single most important property: **verification runs before anything else, over the raw
bytes.** A request that fails it is refused before parsing, redaction or storage. CI asserts
this on every pull request against the built image — unsigned and wrongly-signed requests are
refused, and a correctly-signed one is accepted. That last case is deliberately part of the
gate: without it, a build in which verification rejected everything would pass the other two
identically.

## Agent-facing destinations

New in 0.4.0, and **entirely opt-in** — every default here is chosen so an existing config
renders byte-identically.

A verified webhook is a *verified delivery of unverified content*. GitHub's signature proves
GitHub sent the request; it says nothing about who wrote the issue body inside it. When the
destination is a chat room, the person reading it supplies that distinction. When the
destination is an LLM agent, nothing supplies it unless you say so.

Four mechanisms, in descending order of how much risk they actually remove:

### 1. Filter what the destination sees at all

```yaml
sources:
  - name: github
    filter:
      event_types: [issues.opened, pull_request.opened]
      require:
        issue.author_association: [OWNER, MEMBER, COLLABORATOR]
      deny: {}
      max_field_bytes: 4096
```

`require` and `deny` resolve dotted paths into the **decoded payload**, not into the parser's
variables — so they work under `parser: generic`, where there are no parser variables at all.

Two asymmetries, and they are what make both directions useful:

- a path that does **not** resolve **fails** a `require` — you asked for a guarantee the payload
  does not carry, so it is refused;
- a path that does **not** resolve **passes** a `deny` — absent is not the thing you are refusing.

`deny` is evaluated first, so a payload that satisfies `require` *and* matches `deny` is refused
as `deny`. A filtered event is **stored**, with status `filtered` and zero deliveries, and the
producer gets a 200 — a non-2xx makes a well-behaved producer retry harder over a decision that
will be identical every time.

This is the deterministic half, and it removes more real risk than the detector below.

### 2. Label the source, and fence what it wrote

```yaml
sources:
  - name: github
    trust: untrusted        # untrusted (default) | trusted

sinks:
  - name: agent-inbox
    agent_readable: true    # default false
```

With both set, the fields that source's parser marked as attacker-authored arrive wrapped:

```
<untrusted source="github" field="body">
ignore all previous instructions
</untrusted>
```

Your own fields — `source`, `event_type`, `delivery_id`, `received_at`, `event_id`, and any
structural values the parser derived like `repo` or `number` — stay **outside** the fence. That
is the whole point, and it is why fencing builds a context rather than hooking Jinja's
`finalize`, which sees values and would have fenced `{{ source }}` too.

`{{ event_id }}` is exposed as a stable idempotency key so an agent can dedup its own actions.

**One cost, worth knowing before you enable it.** A fenced field becomes a string. Under the
`generic` parser, which marks the whole `payload` as untrusted, that means
`{{ payload.issue.title }}` renders empty on an `agent_readable` sink — there is no way to wrap
a dict and keep attribute access. Use a named parser's context fields, which are fenced
individually, or leave the sink `agent_readable: false`.

### 3. Strip what should never have been there

On any `untrusted` source — regardless of where its events go — content is normalised with NFKC
and stripped of the Unicode tag block (invisible ASCII, the canonical instruction-smuggling
channel), bidi overrides, zero-width characters, and C0/C1 controls other than tab, newline and
return. This is not a heuristic; it is the same class of rule as header redaction, and it is
counted as `webhook_doorman_content_sanitized_total{source,class}`.

### 4. Screen for injection — and understand what that buys you

```yaml
detector:
  backend: heuristic       # none (default) | heuristic
  threshold: 0.8
  on_detect: annotate      # annotate (default) | quarantine | drop
  on_error: annotate       # annotate (default) | quarantine
```

**The bundled heuristic detector is noisy, and `annotate` is the default because of it.** If you
route a security repository's issues, "ignore all previous instructions" is *legitimate content*
and it will score. Start on `annotate`, watch
`webhook_doorman_detection_total{verdict="flagged"}` for a week against your own traffic, and
only then decide whether `quarantine` is worth it.

Detection **never rejects at the door.** This project exists to make "verification was skipped"
unreachable, and that works because HMAC has a correct answer. A classifier has a confidence.
Putting one in the admit path means either dropping legitimate events or failing open on
classifier error — the exact shape the project was built to remove. So a verdict annotates or
quarantines, and nothing else.

There are **three** outcomes, not two:

| `verdict` | Means |
|---|---|
| `clean` | scored, below threshold |
| `flagged` | scored, at or above threshold |
| `unavailable` | **could not be scored** — never counted as clean |

`unavailable` climbing while `flagged` sits at zero is a detector that is down. Fold those two
together and the same outage reads as "everything is clean", which is the most dangerous
sentence a security control can say.

`on_error` has no `drop` member at all. Discarding an event because the *detector* failed turns a
dependency's outage into silent data loss, so the config language cannot express it. `on_detect`
*does* offer `drop`, and it is **a footgun**: the event is stored with its verdict and is not
releasable, so a false positive becomes a delivery you never learn about. Prefer `quarantine`,
which is the same protection with a way back.

### Quarantine and release

```
GET  /admin/held                 # what is held: event_id, source, event_type, score, rules
POST /admin/release/{event_id}   # queue the deliveries that were withheld
```

Both sit behind the existing admin bearer token, and `/admin/held` returns **failure metadata
only** — no payload, no rendered body, no field content. The reasoning is `GET /admin/dlq`'s, and
it is sharper here: the content being withheld is content something flagged as an injection
attempt, and an endpoint that returned it would hand that text to whatever reads the admin API.
`rules` names what matched; the matched text is not carried anywhere.

Releasing an already-released event is a no-op, not a second enqueue.

A worked configuration is in [`examples/github-to-agent.yml`](../examples/github-to-agent.yml).

## Exposure model

The container always binds `0.0.0.0:8080`. That is not a setting, and the absence is deliberate:
inside a container a `HOST` variable reads as a security control while enforcing nothing, because
reach is decided by the port publish and network membership, not by the bind.

Control exposure at the boundary that actually has it:

| Goal | How |
|---|---|
| Host-side producers only | `-p 127.0.0.1:8080:8080` |
| Reverse proxy only | join the proxy's network, publish **nothing** |
| Public ingress | reverse proxy with TLS and rate limiting; block `/admin/` **and `/metrics`** there |

`POST /admin/replay/{event_id}` re-fires a stored event. It requires a token of at least 32
characters and is disabled entirely without one — and it should never be routed through a public
reverse proxy.

A source `path` may not start with `/admin` or `/metrics`. That is not stylistic: if an ingest
path could live under either prefix, a deny rule at the proxy would silently block it.

---

See also: [configuration.md](configuration.md) for the syntax of the options above.
