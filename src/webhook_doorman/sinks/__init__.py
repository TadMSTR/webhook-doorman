"""Sink registry.

Adding a sink type: a model in `config.py` added to the `SinkSpec` union, a class here, and an
entry in `_BUILDERS`. The union and this table are the two places that must agree — a config
model with no builder fails at startup, which is the right time to find out.
"""

from __future__ import annotations

from ..config import (
    AppriseSink,
    DiscordSink,
    HttpSink,
    MatrixSink,
    NtfySink,
    SinkSpec,
    SlackSink,
    VikunjaTaskSink,
)
from ..errors import ConfigError
from .base import DeliveryOutcome, Sink
from .implementations import (
    AppriseNotifySink,
    DiscordWebhookSink,
    GenericHttpSink,
    MatrixMessageSink,
    NtfySink_,
    SlackWebhookSink,
    VikunjaTaskSink_,
)

_BUILDERS = {
    MatrixSink: MatrixMessageSink,
    NtfySink: NtfySink_,
    VikunjaTaskSink: VikunjaTaskSink_,
    HttpSink: GenericHttpSink,
    DiscordSink: DiscordWebhookSink,
    SlackSink: SlackWebhookSink,
    AppriseSink: AppriseNotifySink,
}


def build_sink(spec: SinkSpec, secrets: dict[str, str]) -> Sink:
    """Instantiate the sink a config entry describes.

    Raises:
        ConfigError: no implementation is registered for this spec type. Startup-time only.
    """
    builder = _BUILDERS.get(type(spec))
    if builder is None:
        raise ConfigError(f"sink {spec.name!r}: no implementation for type {spec.type!r}")
    return builder(spec, secrets)


__all__ = ["DeliveryOutcome", "Sink", "build_sink"]
