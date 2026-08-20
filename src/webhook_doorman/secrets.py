"""Secret resolution and the enabled/disabled state that follows from it.

A structurally-invalid config is a startup crash (see `config.load_config`). A *missing secret*
is not: it disables exactly the source or sink that needed it, is logged as a WARNING at boot,
and is reported by `/health`. A disabled source rejects every request.

The distinction matters. Crashing the whole router because one of five sources lost its variable
turns a partial outage into a total one, while silently enabling that source would be the
fail-open behaviour this project exists to eliminate. Disabling it is the third option, and it is
the only one that is both available and safe.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .config import Config, SinkSpec, SourceConfig, secret_env_names, sink_secret_env_names


@dataclass(frozen=True)
class SourceState:
    """A configured source plus whether it can actually serve requests."""

    config: SourceConfig
    enabled: bool
    disabled_reason: str | None = None
    missing_env: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.config.name


@dataclass(frozen=True)
class SinkState:
    config: SinkSpec
    enabled: bool
    disabled_reason: str | None = None
    missing_env: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.config.name


@dataclass
class Resolved:
    """Everything the app needs at request time, resolved once at startup."""

    config: Config
    secrets: dict[str, str] = field(default_factory=dict)
    sources: dict[str, SourceState] = field(default_factory=dict)
    sinks: dict[str, SinkState] = field(default_factory=dict)

    @property
    def secret_values(self) -> tuple[str, ...]:
        """Every resolved secret value, for redaction. Never logged, never persisted."""
        return tuple(v for v in self.secrets.values() if v)

    def unverified_source_names(self) -> list[str]:
        """Enabled sources running with `strategy: none`, for boot warnings and `/health`."""
        from .config import NoneVerify

        return [
            state.name
            for state in self.sources.values()
            if state.enabled and isinstance(state.config.verify, NoneVerify)
        ]

    def admin_token(self) -> str | None:
        """The replay token, or None when replay is disabled.

        A token shorter than `admin.min_token_length` is treated as absent. A three-character
        token on an endpoint that re-fires real events is worse than no endpoint at all, and an
        operator who set one probably believed it was protecting something.
        """
        name = self.config.admin.token_env
        if not name:
            return None
        value = self.secrets.get(name, "")
        if len(value) < self.config.admin.min_token_length:
            return None
        return value

    def metrics_token(self) -> str | None:
        """The optional `/metrics` token, or None when the endpoint is ungated.

        `None` here means **open**, which is the opposite of `admin_token()` — there, `None`
        disables the endpoint. The asymmetry is deliberate and is the one place this project
        does not fail closed: see `MetricsConfig` for why, and note that a token *configured*
        but too short still returns `None`, so a typo'd gate silently opens the endpoint rather
        than closing it. `log_startup_state` says so out loud at boot for exactly that reason.
        """
        name = self.config.metrics.token_env
        if not name:
            return None
        value = self.secrets.get(name, "")
        if len(value) < self.config.metrics.min_token_length:
            return None
        return value


def _missing(names: list[str], env: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(n for n in names if not env.get(n, "").strip())


def resolve(config: Config, env: Mapping[str, str] | None = None) -> Resolved:
    """Bind a validated config to the environment.

    Args:
        config: a `Config` that has already passed structural validation.
        env: the environment to read. Defaults to `os.environ`; tests pass a dict.

    Returns:
        A `Resolved` carrying the secret values plus per-source and per-sink enabled state.
        Never raises for a missing variable — that is a disable, not a crash.
    """
    env = os.environ if env is None else env

    secrets = {name: env.get(name, "") for name in config.required_env_names()}

    sources: dict[str, SourceState] = {}
    for source in config.sources:
        if not source.enabled:
            sources[source.name] = SourceState(source, False, "disabled in config")
            continue
        missing = _missing(secret_env_names(source.verify), env)
        if missing:
            sources[source.name] = SourceState(
                source,
                False,
                f"missing environment variable(s): {', '.join(missing)}",
                missing,
            )
            continue
        sources[source.name] = SourceState(source, True)

    sinks: dict[str, SinkState] = {}
    for sink in config.sinks:
        missing = _missing(sink_secret_env_names(sink), env)
        if missing:
            sinks[sink.name] = SinkState(
                sink,
                False,
                f"missing environment variable(s): {', '.join(missing)}",
                missing,
            )
            continue
        sinks[sink.name] = SinkState(sink, True)

    return Resolved(config=config, secrets=secrets, sources=sources, sinks=sinks)
