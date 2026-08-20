"""Declarative configuration: sources, sinks and routing.

Two layers, and the split is deliberate:

* **`config.yml`** holds topology — which sources exist, how each is verified, where its events
  go. It is non-secret and safe to commit.
* **The environment** holds secrets. YAML references them *by variable name* (`secret_env`,
  `token_env`, ...), never by value. There is no inline-secret form of any credential field, so
  a leaked `config.yml` leaks nothing but structure.

Adding a source is a YAML entry, not a Python function. That is the whole point of the design:
resist special-casing, or the abstraction stops being real.

Structural problems (unknown sink name, duplicate path, a `none` source without its guard fields)
are **startup** failures — `load_config` raises `ConfigError` naming the file, the source and the
field. A *missing secret* is different: it disables that one source at runtime and is reported by
`/health`, because "verification skipped" must never be reachable but one unset variable should
not take the whole router down.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError
from .redaction import SENSITIVE_HEADERS

MAX_BODY_BYTES_DEFAULT = 1_048_576  # 1 MiB


class _Strict(BaseModel):
    """Base for every config model: unknown keys are an error, not a silent no-op.

    A typo'd key that is quietly ignored is how a verification setting ends up not applied
    while the file still looks correct.
    """

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------------------
# Verification strategies
# --------------------------------------------------------------------------------------


class HmacVerify(_Strict):
    """HMAC-SHA256 over the raw request body.

    Covers GitHub (`sha256=` + hex), Vikunja (bare hex) and most vendors that sign at all.
    """

    strategy: Literal["hmac_sha256"]
    header: str
    secret_env: str
    prefix: str = ""
    encoding: Literal["hex", "base64"] = "hex"

    @field_validator("header", "secret_env")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v


class BearerVerify(_Strict):
    """A shared bearer token in a header. Grafana's usable option, and agent-bus's."""

    strategy: Literal["bearer"]
    secret_env: str
    header: str = "Authorization"
    prefix: str = "Bearer "

    @field_validator("secret_env")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v


class BasicVerify(_Strict):
    """HTTP Basic credentials. Grafana's other option."""

    strategy: Literal["basic"]
    user_env: str
    pass_env: str
    header: str = "Authorization"


class NoneVerify(_Strict):
    """No cryptographic verification — reachability is the only control.

    Three guards, all enforced at startup, because inside a container the old
    "only on a loopback bind" rule is meaningless: the app always binds `0.0.0.0` and exposure
    is a property of the port publish and network membership. A check that cannot fail is a
    control in name only.

    1. The top-level `server.allow_unverified` must be `true`.
    2. This source must carry a non-blank `unverified_reason`.
    3. `allow_from` must be present and non-empty. There is no allow-all form: an omitted or
       empty list is a startup error, not a wildcard. Use `["127.0.0.1/32"]` unless you have a
       specific reason to widen it.

    `allow_from` is matched against the **socket peer address**, never `X-Forwarded-For` — a
    forwarded-for header is set by the client on a direct connection and would make the
    allowlist trivially forgeable.
    """

    strategy: Literal["none"]
    unverified_reason: str
    allow_from: list[str]

    @field_validator("unverified_reason")
    @classmethod
    def _reason_non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError(
                "must state why this source is unverified — a blank reason defeats the guard"
            )
        return v

    @field_validator("allow_from")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError(
                "must list at least one CIDR — an empty allow_from is a startup error, "
                "not an allow-all"
            )
        for entry in v:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"{entry!r} is not a valid CIDR: {exc}") from exc
        return v

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parsed form of `allow_from`, for peer matching."""
        return [ipaddress.ip_network(entry, strict=False) for entry in self.allow_from]


VerifySpec = Annotated[
    HmacVerify | BearerVerify | BasicVerify | NoneVerify,
    Field(discriminator="strategy"),
]


def secret_env_names(spec: VerifySpec) -> list[str]:
    """Every environment variable this strategy needs. Empty for `none`.

    Checked against `sink_secret_env_names`'s failure mode and it is exhaustive over today's
    union — but only because every member is named here. A fifth strategy carrying a `*_env`
    field would fall through to `return []` and be just as silently invisible, so
    `test_verify_union_env_coverage` asserts exhaustiveness rather than leaving it to review.
    """
    if isinstance(spec, HmacVerify | BearerVerify):
        return [spec.secret_env]
    if isinstance(spec, BasicVerify):
        return [spec.user_env, spec.pass_env]
    return []


# --------------------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------------------


class DedupConfig(_Strict):
    """How to derive the delivery ID that dedup keys on.

    When `id_header` is unset, or the producer omits it, the ID falls back to a SHA-256 of the
    raw body. That keeps dedup universal rather than a per-vendor privilege — a producer that
    does not send a delivery header still cannot double-post an identical payload.
    """

    id_header: str | None = None
    enabled: bool = True


class SourceConfig(_Strict):
    name: str
    path: str
    verify: VerifySpec
    sinks: list[str]
    parser: str = "generic"
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    enabled: bool = True

    @field_validator("path")
    @classmethod
    def _leading_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError(f"path must start with '/' (got {v!r})")
        if v.startswith("/admin"):
            raise ValueError(
                "path must not live under /admin — that prefix is reserved for the "
                "authenticated admin API and is expected to be blocked at the reverse proxy"
            )
        return v

    @field_validator("name")
    @classmethod
    def _name_non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v

    @field_validator("sinks")
    @classmethod
    def _at_least_one_sink(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("must route to at least one sink")
        return v

    @model_validator(mode="after")
    def _dedup_header_is_not_a_credential(self):
        """The dedup key must not be a credential header.

        Two things go wrong if it is. The value is redacted before storage, so every event
        would dedup to the same key and the second one onwards would be silently discarded —
        a dedup config that deletes traffic. And if it were *not* redacted, the credential
        would be written to the event log as the delivery id.
        """
        header = (self.dedup.id_header or "").lower()
        if not header:
            return self
        verify_header = getattr(self.verify, "header", "").lower()
        if header in SENSITIVE_HEADERS or (verify_header and header == verify_header):
            raise ValueError(
                f"dedup.id_header {self.dedup.id_header!r} is a credential header; it is "
                f"redacted before storage, so using it as the dedup key would collapse every "
                f"event onto one id. Use the producer's delivery-id header, or omit dedup."
            )
        return self


# --------------------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------------------


class _SinkBase(_Strict):
    name: str

    @field_validator("name")
    @classmethod
    def _name_non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v


class _EndpointMixin(BaseModel):
    """Exactly one of `url` / `url_env` on a sink that talks to an HTTP endpoint.

    A plain URL is not a secret, so an adopter may write it inline. Keeping the `url_env` form
    available lets a deployment hold its topology in the environment alongside its credentials —
    which is what makes this repo publishable while the operator's own endpoints stay private.
    """

    url: str | None = None
    url_env: str | None = None

    @model_validator(mode="after")
    def _exactly_one_url(self):
        if bool(self.url) == bool(self.url_env):
            raise ValueError("set exactly one of 'url' or 'url_env'")
        return self


class MatrixSink(_SinkBase, _EndpointMixin):
    """Post a message into a Matrix room.

    The room ID is a `*_env` reference rather than an inline value because a room ID is
    deployment topology, and leaking one into a public repo has a real precedent.
    """

    type: Literal["matrix"]
    token_env: str
    room_env: str
    template: str = "{{ summary }}"


class NtfySink(_SinkBase, _EndpointMixin):
    type: Literal["ntfy"]
    topic_env: str
    token_env: str | None = None
    title_template: str = "{{ source }}"
    template: str = "{{ summary }}"
    tags: str = "bell"


class VikunjaTaskSink(_SinkBase, _EndpointMixin):
    type: Literal["vikunja_task"]
    token_env: str
    project_id: int
    title_template: str = "{{ summary }}"
    description_template: str = "{{ summary }}"

    @field_validator("project_id")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("must be a positive project id")
        return v


class HttpSink(_SinkBase, _EndpointMixin):
    """Generic POST with a rendered body. The escape hatch that keeps bespoke sinks unnecessary."""

    type: Literal["http"]
    method: Literal["POST", "PUT", "PATCH"] = "POST"
    content_type: str = "application/json"
    template: str = "{}"
    token_env: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


SinkSpec = Annotated[
    MatrixSink | NtfySink | VikunjaTaskSink | HttpSink,
    Field(discriminator="type"),
]


def sink_secret_env_names(sink: SinkSpec) -> list[str]:
    """Environment variables a sink needs before it can be used.

    Derived from the model rather than from a literal attribute list. A hardcoded tuple
    silently misses any new `*_env` field, and the resulting failure is quiet rather than
    loud: a sink whose credential is not discovered here is reported `enabled: true` at
    `/health` with its variable unset, and its value never enters `resolved.secret_values`,
    so it is never redacted from the event log. A sink author who adds `webhook_url_env`
    should not also have to remember to register it in a second place.
    """
    return [
        value
        for name in type(sink).model_fields
        if name.endswith("_env") and (value := getattr(sink, name, None))
    ]


# --------------------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------------------


class ServerConfig(_Strict):
    max_body_bytes: int = MAX_BODY_BYTES_DEFAULT
    allow_unverified: bool = False

    @field_validator("max_body_bytes")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("must be positive")
        return v


class StorageConfig(_Strict):
    """Where the event log lives.

    SQLite in WAL mode, embedded, one file. Postgres and Redis are named extension points in
    ARCHITECTURE.md, not options here — see `store.base.Store` for the seam they would plug into.
    """

    path: str = "/data/webhook-doorman.db"
    retention_days: int = 30
    dlq_retention_days: int = 90
    sweep_interval_seconds: float = 3600.0


class DeliveryConfig(_Strict):
    max_attempts: int = 5
    base_backoff_seconds: float = 2.0
    max_backoff_seconds: float = 300.0
    jitter: float = 0.25
    timeout_seconds: float = 10.0
    poll_interval_seconds: float = 1.0

    @field_validator("max_attempts")
    @classmethod
    def _at_least_one(cls, v: int) -> int:
        if v < 1:
            raise ValueError("must be at least 1")
        return v


class AdminConfig(_Strict):
    """The replay API.

    Disabled unless `token_env` is set *and* that variable holds a value — replay re-fires real
    events, so it fails closed in exactly the same way a source does.
    """

    token_env: str | None = None
    min_token_length: int = 32


class Config(_Strict):
    sources: list[SourceConfig]
    sinks: list[SinkSpec]
    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    delivery: DeliveryConfig = Field(default_factory=DeliveryConfig)
    admin: AdminConfig = Field(default_factory=AdminConfig)

    @model_validator(mode="after")
    def _cross_check(self):
        problems: list[str] = []

        if not self.sources:
            problems.append("sources: at least one source must be defined")

        problems.extend(_duplicates("source name", [s.name for s in self.sources]))
        problems.extend(_duplicates("source path", [s.path for s in self.sources]))
        problems.extend(_duplicates("sink name", [s.name for s in self.sinks]))

        known_sinks = {s.name for s in self.sinks}
        for source in self.sources:
            for sink_name in source.sinks:
                if sink_name not in known_sinks:
                    problems.append(
                        f"source {source.name!r}: sinks references unknown sink {sink_name!r} "
                        f"(defined sinks: {sorted(known_sinks) or 'none'})"
                    )

        # The `none` guard. Collected across all sources so one startup reports every offender
        # rather than making the operator fix them one boot at a time.
        unverified = [s for s in self.sources if isinstance(s.verify, NoneVerify)]
        if unverified and not self.server.allow_unverified:
            names = ", ".join(repr(s.name) for s in unverified)
            problems.append(
                f"server.allow_unverified is false but these sources use strategy 'none': "
                f"{names}. Set server.allow_unverified: true to acknowledge this deliberately, "
                f"or give them a real verification strategy."
            )

        if problems:
            raise ValueError("; ".join(problems))
        return self

    def source_by_name(self, name: str) -> SourceConfig | None:
        return next((s for s in self.sources if s.name == name), None)

    def sink_by_name(self, name: str) -> SinkSpec | None:
        return next((s for s in self.sinks if s.name == name), None)

    def required_env_names(self) -> set[str]:
        """Every environment variable referenced anywhere in this config."""
        names: set[str] = set()
        for source in self.sources:
            names.update(secret_env_names(source.verify))
        for sink in self.sinks:
            names.update(sink_secret_env_names(sink))
        if self.admin.token_env:
            names.add(self.admin.token_env)
        return names


def _duplicates(label: str, values: list[str]) -> list[str]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for value in values:
        if value in seen:
            dupes.add(value)
        seen.add(value)
    return [f"duplicate {label}: {v!r}" for v in sorted(dupes)]


def load_config(path: str | Path) -> Config:
    """Parse and validate `config.yml`.

    Raises:
        ConfigError: the file is missing, is not a YAML mapping, or fails validation. The
            message names the file and every offending field, because a config error the
            operator has to bisect is barely better than no message at all.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    if data is None:
        raise ConfigError(f"{path} is empty")
    if not isinstance(data, dict):
        raise ConfigError(
            f"{path} must contain a mapping at the top level, got {type(data).__name__}"
        )

    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{path} is invalid:\n{_format_errors(exc)}") from exc


def _format_errors(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        location = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"  - {location}: {err['msg']}")
    return "\n".join(lines)
