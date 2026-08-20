"""structlog configuration: JSON to stdout, which is what a container runtime wants."""

from __future__ import annotations

import logging
import os

import structlog


def configure_logging(level: str | None = None) -> None:
    """Configure structlog once, at startup.

    Args:
        level: log level name. Defaults to `$LOG_LEVEL`, then INFO.
    """
    level_name = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    logging.basicConfig(format="%(message)s", level=getattr(logging, level_name, logging.INFO))
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level_name, logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
