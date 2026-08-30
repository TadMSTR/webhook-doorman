"""structlog configuration: JSON to stdout, which is what a container runtime wants."""

from __future__ import annotations

import logging
import os
import time

import structlog


def configure_logging(level: str | None = None, log_format: str | None = None) -> None:
    """Configure structlog once, at startup.

    Args:
        level: log level name. Defaults to `$LOG_LEVEL`, then INFO.
        log_format: `json` or `console`. Defaults to `$LOG_FORMAT`, then `json`.

    JSON stays the default deliberately. This runs as a container, the log is a stream something
    else parses, and flipping that default would break anyone's ingestion for the benefit of
    whoever is reading a terminal. `console` is opt-in for local development.
    """
    level_name = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    format_name = (log_format or os.environ.get("LOG_FORMAT") or "json").lower()
    renderer: structlog.typing.Processor = (
        structlog.dev.ConsoleRenderer()
        if format_name == "console"
        else structlog.processors.JSONRenderer()
    )

    logging.basicConfig(format="%(message)s", level=getattr(logging, level_name, logging.INFO))
    structlog.configure(
        processors=[
            # First in the chain, and it has to be: it merges the request-scoped context that
            # `build_source_route` binds. Without it, every `bind_contextvars` call in this
            # package is a silent no-op and a 401 line goes out with no source on it.
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level_name, logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


#: Seconds between repeats of the same throttled key. One minute: long enough that an hour of
#: a down dependency is ~60 lines rather than one per event, short enough that the line is still
#: present in whatever window an operator is looking at.
THROTTLE_INTERVAL_SECONDS = 60.0

_last_emitted: dict[str, float] = {}


def log_throttled(logger, key: str, event: str, /, **fields) -> bool:
    """Emit `event` at warning level at most once per `key` per interval.

    A degraded dependency produces one log line per *event* if you let it, and at webhook volume
    that buries the rest of the log in a repetition of one fact. Ported in spirit from
    `searxng-mcp`'s `logThrottled`, including the shape of the key: `degrade:<what>`, so the
    thing being suppressed is greppable and so two different degradations never share a budget.

    Returns:
        True if the line was emitted, False if it was suppressed. Returned so a caller can count
        suppressions without the throttle having to know what a metric is.
    """
    now = time.monotonic()
    previous = _last_emitted.get(key)
    if previous is not None and (now - previous) < THROTTLE_INTERVAL_SECONDS:
        return False
    _last_emitted[key] = now
    logger.warning(event, throttle_key=key, **fields)
    return True


def reset_throttle() -> None:
    """Forget every throttle key. For tests — a live router has no reason to call this."""
    _last_emitted.clear()
