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
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any, Protocol

import structlog
from fastapi import APIRouter, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from . import __version__
from .config import Config, NoneVerify, load_config
from .models import InboundEvent
from .parsers import get_parser, parse
from .redaction import redact_bytes, redact_headers, redact_json, redact_text
from .secrets import Resolved, SourceState, resolve
from .verification import verify

log = structlog.get_logger(__name__)

IngestFn = Callable[[InboundEvent], Awaitable[dict[str, Any]]]


class EngineLike(Protocol):
    """What `create_app` needs from an engine.

    A protocol rather than the concrete class so the app layer stays free of storage and
    delivery concerns, and so tests can drive routes with a stub.
    """

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def ingest(self, event: InboundEvent) -> dict[str, Any]: ...
    async def replay(self, event_id: int) -> dict[str, Any]: ...
    async def stats(self) -> dict[str, int]: ...
    def check_admin_token(self, presented: str) -> bool: ...


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


# A delivery ID is a producer's opaque handle — GitHub's is a UUID, most are shorter. This is
# the value that goes into a unique index and every log line for the event, and it arrives in a
# header we do not control, so it gets an upper bound. Anything longer is truncated rather than
# rejected: the truncation is deterministic, so dedup still works, and refusing the delivery
# over a long header would be a worse outcome than a coarser key.
MAX_DELIVERY_ID_LENGTH = 200


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
            return value[:MAX_DELIVERY_ID_LENGTH]
    return "sha256:" + hashlib.sha256(body).hexdigest()


async def _log_only_ingest(event: InboundEvent) -> dict[str, Any]:
    """Fallback ingest used when no engine is wired in (tests, config validation runs).

    `source` and `delivery_id` are not passed explicitly: the handler has them bound as
    request-scoped context, and repeating them here would mask a broken binding behind a line
    that looks correct.
    """
    log.info("event_accepted", event_type=event.event_type, sinks=event.sinks)
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
        # Everything logged inside this block carries the source, and — once it is known — the
        # delivery id. Without it a 401 or a 413 line names the source and nothing else, which
        # is not enough to correlate a rejection with the request that caused it.
        #
        # `bound_contextvars` rather than a bare `bind`/`clear` pair: it restores what was there
        # before and touches no other key, so a leaked binding cannot attach one request's ids
        # to another's log lines. Requests already run in separate asyncio tasks and therefore
        # separate contexts, but that is a property of the server, not of this handler.
        with structlog.contextvars.bound_contextvars(source=source.name):
            if not state.enabled:
                # 503, not 401: the caller's credentials were never the problem, and a producer
                # that distinguishes them can back off instead of rotating a working secret.
                log.warning("source_disabled_rejected", reason=state.disabled_reason)
                raise HTTPException(status_code=503, detail="Source is not available")

            try:
                body = await read_body_capped(request, max_body)
            except BodyTooLarge:
                log.warning("body_too_large", limit=max_body)
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
                log.warning("verification_failed", reason=result.reason)
                raise HTTPException(status_code=401, detail="Unauthorized")

            # Redact once, here, and derive everything downstream from the redacted bytes.
            # Parsing the raw body and redacting the result afterwards is the same work with a
            # hole in it: a parser lifts nested payload fields into `context`, and a redaction
            # pass that covers `body` but not `context` writes the secret to disk in the field
            # nobody was looking at.
            secret_values = resolved.secret_values
            safe_body = redact_bytes(body, secret_values)
            parsed = parse(parser_name, safe_body, headers)
            delivery_id = compute_delivery_id(state, headers, safe_body)

            with structlog.contextvars.bound_contextvars(delivery_id=delivery_id):
                event = InboundEvent(
                    source=source.name,
                    delivery_id=delivery_id,
                    event_type=parsed.event_type,
                    summary=redact_text(parsed.summary, secret_values),
                    headers=redact_headers(
                        headers, extra_headers=credential_headers, secret_values=secret_values
                    ),
                    body=safe_body,
                    payload=_safe_json(safe_body),
                    context=redact_json(parsed.context, secret_values),
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


def build_admin_router(engine: EngineLike) -> APIRouter:
    """The replay API.

    Two independent controls, because replay re-fires real events at real destinations:

    * A bearer token of at least `admin.min_token_length` characters. Absent or short means the
      endpoint rejects everything — `check_admin_token` returns False rather than opening up.
    * The `/admin/` prefix, which is expected to be blocked at the reverse proxy. Source paths
      are forbidden from living under it, so the deny rule cannot accidentally shadow ingest.

    Note the token is checked before the event id is looked up, so an unauthenticated caller
    cannot use response codes to probe which event ids exist.
    """
    router = APIRouter(prefix="/admin", tags=["admin"])

    @router.post("/replay/{event_id}")
    async def replay(event_id: int, authorization: str = Header(default="")) -> dict[str, Any]:
        presented = authorization.removeprefix("Bearer ").strip()
        if not engine.check_admin_token(presented):
            log.warning("admin_auth_failed", path=f"/admin/replay/{event_id}")
            raise HTTPException(status_code=401, detail="Unauthorized")
        try:
            return await engine.replay(event_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="Event not found") from exc

    return router


def build_health_route(
    resolved: Resolved, engine: EngineLike | None = None
) -> Callable[[Response], Awaitable[dict[str, Any]]]:
    """`/health`: liveness plus the per-source enabled state and any unverified sources.

    Unverified sources are named here on purpose. `allow_unverified` is an acknowledgement, not
    an amnesty — an operator should be able to see at a glance which endpoints are accepting
    traffic on reachability alone.

    **The status code carries a verdict**, because `Dockerfile`'s HEALTHCHECK polls this route:
    a body that always says `ok` makes the container's health status unable to fail for any
    reason short of the process dying. It returns **503** when the router cannot do its job at
    all — no source is enabled, or the store is unreachable.

    A *partially* degraded router stays **200**. One disabled source out of three is usually a
    deliberate state (a secret not yet provisioned, a source retired in place), and flapping the
    container on it would replace one wrong answer with a noisier one. The disabled source is
    still named in the body, which is where that belongs.

    `engine` is optional so the log-only path — `create_app` without an engine — keeps a route
    that has no storage concern at all rather than growing a null-store branch.
    """

    async def health(response: Response) -> dict[str, Any]:
        body: dict[str, Any] = {
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

        degraded: list[str] = []
        if not any(state.enabled for state in resolved.sources.values()):
            degraded.append("no sources are enabled")

        if engine is not None:
            try:
                body["stats"] = await engine.stats()
            except Exception as exc:
                # A store that cannot be queried is the "not connected" condition, and it is a
                # real degradation. It must not be a 500 though: this is the liveness endpoint,
                # and an unhandled exception here reports the same thing as a dead process.
                log.warning("health_stats_failed", error=str(exc))
                degraded.append("store is unavailable")

        if degraded:
            body["status"] = "degraded"
            body["degraded"] = degraded
            response.status_code = 503

        return body

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
    engine: EngineLike | None = None,
    resolved: Resolved | None = None,
) -> FastAPI:
    """Build the application from a config.

    Args:
        config: an already-loaded config. Mutually exclusive with `config_path`.
        config_path: path to `config.yml`.
        env: environment to resolve secrets from. Defaults to `os.environ`.
        resolved: an already-resolved config. Pass this when an engine was built from the same
            resolution, so the app and the engine cannot disagree about which sinks are enabled.
        ingest: what to do with a verified event. Defaults to the engine's `ingest` when one is
            supplied, and to log-only otherwise.
        engine: the delivery engine. When present its lifecycle is bound to the app's, and the
            `/admin` router is mounted.

    Returns:
        A FastAPI app with one POST route per source, `/health`, and `/admin` if an engine
        was supplied.
    """
    if resolved is None:
        if config is None:
            if config_path is None:
                raise ValueError("provide either config or config_path")
            config = load_config(config_path)
        resolved = resolve(config, env)
    log_startup_state(resolved)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if engine is not None:
            await engine.start()
        try:
            yield
        finally:
            if engine is not None:
                await engine.stop()

    app = FastAPI(
        title="webhook-doorman",
        version=__version__,
        description="A fail-closed inbound webhook router.",
        lifespan=lifespan,
    )
    app.state.resolved = resolved
    app.state.engine = engine

    router = APIRouter()
    router.add_api_route("/health", build_health_route(resolved, engine), methods=["GET"])

    handler = ingest or (engine.ingest if engine is not None else _log_only_ingest)
    for name, state in resolved.sources.items():
        router.add_api_route(
            state.config.path,
            build_source_route(state, resolved, handler),
            methods=["POST"],
            name=f"source_{name}",
            summary=f"Ingest for source {name!r}",
        )

    app.include_router(router)
    if engine is not None:
        app.include_router(build_admin_router(engine))
    return app
