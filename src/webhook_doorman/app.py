"""The FastAPI application: one route per configured source, plus `/health`.

Request flow, and the order is the design:

    read body (capped)  ->  verify  ->  parse  ->  redact  ->  ingest

Verification happens against the **raw bytes as received**, before any JSON decoding, because a
signature over a re-serialised payload is not a signature. Redaction happens before the event
object exists at all, so there is no window in which an un-redacted event could reach the store.

A source is either enabled or it rejects. There is no third state, and in particular there is no
"secret missing, verification skipped" — the failure this project was built to eliminate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import structlog
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from . import __version__
from .config import Config, NoneVerify, load_config
from .models import InboundEvent
from .parsers import get_parser, parse
from .redaction import redact_bytes, redact_headers
from .secrets import Resolved, SourceState, resolve
from .verification import verify

log = structlog.get_logger(__name__)

IngestFn = Callable[[InboundEvent], Awaitable[dict[str, Any]]]


class BodyTooLarge(Exception):
    """The request body exceeded `server.max_body_bytes`."""


async def read_body_capped(request: Request, limit: int) -> bytes:
    """Read the body, refusing anything over `limit`.

    The declared `Content-Length` is checked first so an oversized upload is rejected before a
    byte of it is read, and the stream is then capped anyway — a chunked request has no
    Content-Length to check, and a lying one is exactly the case the cap exists for.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise BodyTooLarge
        except ValueError:
            raise BodyTooLarge from None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def lowered_headers(request: Request) -> dict[str, str]:
    """Request headers with lowercased keys. Starlette already lowercases; this is explicit."""
    return {k.lower(): v for k, v in request.headers.items()}


def peer_address(request: Request) -> str | None:
    """The socket peer address.

    Deliberately not derived from `X-Forwarded-For`. `allow_from` on an unverified source is a
    reachability control, and a control a caller can set a header to bypass is not one. Run
    uvicorn without `--proxy-headers` (the packaged entry point does) so this stays true.
    """
    return request.client.host if request.client else None


def compute_delivery_id(state: SourceState, headers: Mapping[str, str], body: bytes) -> str:
    """Derive the ID that dedup keys on.

    Prefers the producer's own delivery header. Falls back to a digest of the body so a
    producer that sends no such header still cannot double-post an identical payload — dedup
    should not be a privilege reserved for well-behaved vendors.
    """
    header_name = state.config.dedup.id_header
    if header_name:
        value = headers.get(header_name.lower(), "").strip()
        if value:
            return value
    return "sha256:" + hashlib.sha256(body).hexdigest()


async def _log_only_ingest(event: InboundEvent) -> dict[str, Any]:
    """Fallback ingest used when no engine is wired in (tests, config validation runs)."""
    log.info(
        "event_accepted",
        source=event.source,
        event_type=event.event_type,
        delivery_id=event.delivery_id,
        sinks=event.sinks,
    )
    return {"status": "accepted"}


def build_source_route(
    state: SourceState,
    resolved: Resolved,
    ingest: IngestFn,
) -> Callable[[Request], Awaitable[Response]]:
    """Build the handler for one source. Closes over resolved state — no per-request lookups."""
    source = state.config
    parser_name = source.parser
    get_parser(parser_name)  # fail at startup, not at first request
    credential_headers = [getattr(source.verify, "header", "")]
    max_body = resolved.config.server.max_body_bytes

    async def handler(request: Request) -> Response:
        if not state.enabled:
            # 503, not 401: the caller's credentials were never the problem, and a producer
            # that distinguishes them can back off instead of rotating a working secret.
            log.warning(
                "source_disabled_rejected", source=source.name, reason=state.disabled_reason
            )
            raise HTTPException(status_code=503, detail="Source is not available")

        try:
            body = await read_body_capped(request, max_body)
        except BodyTooLarge:
            log.warning("body_too_large", source=source.name, limit=max_body)
            raise HTTPException(status_code=413, detail="Payload too large") from None

        headers = lowered_headers(request)
        result = verify(
            source.verify,
            body=body,
            headers=headers,
            peer=peer_address(request),
            secrets=resolved.secrets,
        )
        if not result.ok:
            # The reason goes to the log, never to the caller.
            log.warning("verification_failed", source=source.name, reason=result.reason)
            raise HTTPException(status_code=401, detail="Unauthorized")

        parsed = parse(parser_name, body, headers)

        secret_values = resolved.secret_values
        event = InboundEvent(
            source=source.name,
            delivery_id=compute_delivery_id(state, headers, body),
            event_type=parsed.event_type,
            summary=parsed.summary,
            headers=redact_headers(
                headers, extra_headers=credential_headers, secret_values=secret_values
            ),
            body=redact_bytes(body, secret_values),
            payload=_safe_json(body),
            context=parsed.context,
            sinks=list(source.sinks) if parsed.actionable else [],
            verified=not isinstance(source.verify, NoneVerify),
        )

        payload = await ingest(event)
        return JSONResponse(status_code=200, content=payload)

    handler.__name__ = f"source_{source.name}"
    return handler


def _safe_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def build_health_route(resolved: Resolved) -> Callable[[], Awaitable[dict[str, Any]]]:
    """`/health`: liveness plus the per-source enabled state and any unverified sources.

    Unverified sources are named here on purpose. `allow_unverified` is an acknowledgement, not
    an amnesty — an operator should be able to see at a glance which endpoints are accepting
    traffic on reachability alone.
    """

    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "sources": {
                name: {
                    "enabled": state.enabled,
                    "path": state.config.path,
                    "strategy": state.config.verify.strategy,
                    **({"reason": state.disabled_reason} if not state.enabled else {}),
                }
                for name, state in resolved.sources.items()
            },
            "sinks": {
                name: {
                    "enabled": state.enabled,
                    "type": state.config.type,
                    **({"reason": state.disabled_reason} if not state.enabled else {}),
                }
                for name, state in resolved.sinks.items()
            },
            "unverified_sources": resolved.unverified_source_names(),
            "replay_enabled": resolved.admin_token() is not None,
        }

    return health


def log_startup_state(resolved: Resolved) -> None:
    """Announce disabled sources and unverified sources at boot.

    Both are conditions an operator needs to notice without going looking, and a WARNING in the
    first ten lines of a container log is the only place they reliably will.
    """
    for name, state in resolved.sources.items():
        if not state.enabled:
            log.warning("source_disabled", source=name, reason=state.disabled_reason)
    for name, state in resolved.sinks.items():
        if not state.enabled:
            log.warning("sink_disabled", sink=name, reason=state.disabled_reason)

    for name in resolved.unverified_source_names():
        spec = resolved.sources[name].config.verify
        if not isinstance(spec, NoneVerify):  # pragma: no cover - narrowed by the caller
            continue
        log.warning(
            "source_unverified",
            source=name,
            reason=spec.unverified_reason,
            allow_from=spec.allow_from,
        )

    if resolved.config.admin.token_env and resolved.admin_token() is None:
        log.warning(
            "replay_disabled",
            reason=(
                f"{resolved.config.admin.token_env} is unset or shorter than "
                f"{resolved.config.admin.min_token_length} characters"
            ),
        )


def create_app(
    *,
    config: Config | None = None,
    config_path: str | None = None,
    env: Mapping[str, str] | None = None,
    ingest: IngestFn | None = None,
) -> FastAPI:
    """Build the application from a config.

    Args:
        config: an already-loaded config. Mutually exclusive with `config_path`.
        config_path: path to `config.yml`.
        env: environment to resolve secrets from. Defaults to `os.environ`.
        ingest: what to do with a verified event. Defaults to log-only; the engine supplies the
            persisting implementation.

    Returns:
        A FastAPI app with one POST route per source and a `/health` route.
    """
    if config is None:
        if config_path is None:
            raise ValueError("provide either config or config_path")
        config = load_config(config_path)

    resolved = resolve(config, env)
    log_startup_state(resolved)

    app = FastAPI(
        title="webhook-doorman",
        version=__version__,
        description="A fail-closed inbound webhook router.",
    )
    app.state.resolved = resolved

    router = APIRouter()
    router.add_api_route("/health", build_health_route(resolved), methods=["GET"])

    handler = ingest or _log_only_ingest
    for name, state in resolved.sources.items():
        router.add_api_route(
            state.config.path,
            build_source_route(state, resolved, handler),
            methods=["POST"],
            name=f"source_{name}",
            summary=f"Ingest for source {name!r}",
        )

    app.include_router(router)
    return app
