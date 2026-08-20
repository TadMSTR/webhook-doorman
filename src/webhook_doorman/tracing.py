"""Optional OpenTelemetry tracing.

**Off unless explicitly configured, and never fatal.** Two conditions must both hold before a
single span is produced: `OTEL_EXPORTER_OTLP_ENDPOINT` is set, and the `[otel]` extra is
installed. If the variable is set and the packages are missing, that is a **warning at boot**
and the router serves traffic exactly as before — telemetry is not worth taking a webhook
router down for, and the failure mode of "refuses to start in production because an optional
extra is absent" is worse than the one it prevents.

The default install therefore stays at nine dependencies. The published image includes the
extra, so enabling tracing there is one environment variable and no rebuild.

**Nothing from a payload goes on a span.** Not body content, not headers, not rendered template
output. `redaction.py` exists because that material leaks; a span exporter is simply another
egress and the same rule applies to it. The attributes below are all either config-derived
(`source`, `sink`) or structural (`attempt`, `response_code`, `latency_ms`) — the same
vocabulary the metrics labels use, and for the same reason.

**Fork safety.** The SDK's `BatchSpanProcessor` spawns a background thread that is not
fork-safe, which is why SigNoz's Python docs recommend Gunicorn-with-Uvicorn-workers for
multi-worker ASGI servers. That hazard does not apply here: `__main__.py` calls `uvicorn.run`
with no `workers` argument, so there is one process and no fork, and configuring the SDK
in-process is safe. The constraint that creates is recorded next to `uvicorn.run` itself —
adding `--workers` later would silently break tracing.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator, Sequence
from typing import Any

import structlog

from .redaction import redact_text

log = structlog.get_logger(__name__)

#: The variable that turns tracing on. Named by the OTel spec, not by us, so an operator's
#: existing OTLP configuration works without translation.
ENDPOINT_VAR = "OTEL_EXPORTER_OTLP_ENDPOINT"
SERVICE_NAME_VAR = "OTEL_SERVICE_NAME"
DEFAULT_SERVICE_NAME = "webhook-doorman"

_tracer: Any | None = None


def configure(
    app: Any = None,
    env: dict[str, str] | None = None,
    secret_values: Sequence[str] = (),
) -> bool:
    """Set up the OTel SDK if it is both wanted and available.

    Args:
        app: the FastAPI app to instrument, if the FastAPI instrumentation is installed.
        env: environment to read. Defaults to `os.environ`.
        secret_values: resolved secret values, scrubbed from auto-instrumented span attributes.
            **Pass `resolved.secret_values` here.** Omitting it does not fail loudly — it
            silently exports a Discord or Slack webhook URL, which is the credential. See
            `_redacting_hook`.

    Returns:
        True if tracing is now active. False for every "not configured" and "not installed"
        case — this function does not raise for either.
    """
    global _tracer

    environ = os.environ if env is None else env
    endpoint = environ.get(ENDPOINT_VAR, "").strip()
    if not endpoint:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        # Loud, and not fatal. `log_startup_state` puts its warnings in the first few lines of
        # the container log for the same reason: this is a condition an operator needs to
        # notice without going looking for it.
        log.warning(
            "tracing_unavailable",
            reason=(
                f"{ENDPOINT_VAR} is set but the OpenTelemetry packages are not installed — "
                f"install webhook-doorman[otel] to enable tracing"
            ),
            error=str(exc),
        )
        return False

    service_name = environ.get(SERVICE_NAME_VAR, "").strip() or DEFAULT_SERVICE_NAME
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(DEFAULT_SERVICE_NAME)

    _instrument(app, secret_values)
    log.info("tracing_enabled", endpoint=endpoint, service_name=service_name)
    return True


def _redacting_hook(secret_values: Sequence[str]) -> Any:
    """A span hook that strips resolved secrets from every string attribute.

    **This is what stops the httpx auto-instrumentation exporting a sink credential.** It
    captures the full request URL as a span attribute, and for Discord and Slack the webhook
    URL *is* the credential — the same fact that makes `follow_redirects=False` load-bearing.
    For the apprise sink the credential is the `key` path segment. Without this, enabling
    tracing would export all of them to the collector on every delivery attempt, outside this
    project's redaction boundary entirely.

    **Redacts by value, not by attribute name.** Scrubbing a known key like `http.url` would be
    a denylist against a moving target: the instrumentation is mid-migration from `http.url` to
    `url.full`, and a rename would silently reopen the leak while the code still looked correct.
    Matching on the secret values themselves does not care what the attribute is called, so a
    renamed or newly-added attribute is covered the day it appears.

    The apprise case shows why this is the right granularity: only the key substring is replaced,
    so the base URL stays legible as topology and the trace remains useful.
    """

    def scrub(span: Any, _request: Any) -> None:
        if not span.is_recording():
            return
        for key, value in list(span.attributes.items()):
            if isinstance(value, str):
                cleaned = redact_text(value, secret_values)
                if cleaned != value:
                    span.set_attribute(key, cleaned)

    async def scrub_async(span: Any, request: Any) -> None:
        scrub(span, request)

    return scrub, scrub_async


def _instrument(app: Any, secret_values: Sequence[str] = ()) -> None:
    """Auto-instrument FastAPI and httpx when those extras are present.

    Separately guarded from the SDK import: the instrumentation packages version independently
    of the SDK, and losing the server-span integration is not a reason to lose manual spans too.
    """
    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app)
        except ImportError:  # pragma: no cover - exercised only without the extra
            log.warning("tracing_fastapi_instrumentation_unavailable")
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        scrub, scrub_async = _redacting_hook(secret_values)
        # Both hooks, deliberately. The delivery client is an `httpx.AsyncClient`, and the
        # async path only consults `async_request_hook` — passing `request_hook` alone is a
        # silent no-op that leaves the URL exported while looking like a fix. Registering both
        # means a synchronous client added later is covered rather than quietly unprotected.
        HTTPXClientInstrumentor().instrument(request_hook=scrub, async_request_hook=scrub_async)
    except ImportError:  # pragma: no cover - exercised only without the extra
        log.warning("tracing_httpx_instrumentation_unavailable")


def enabled() -> bool:
    return _tracer is not None


def reset() -> None:
    """Forget the tracer. For tests — a live router has no reason to call this."""
    global _tracer
    _tracer = None


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """A span, or a no-op when tracing is off.

    The no-op path is the one that runs for almost every adopter, so it is deliberately the
    cheapest thing that can work: one `is None` check and a bare yield, no context manager
    stack, no attribute dictionary built.

    Attributes must be config-derived or structural. See the module docstring — nothing from a
    payload, a header or a rendered template goes on a span.
    """
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        yield current
