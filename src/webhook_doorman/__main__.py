"""Console entry point.

The bind address is not configurable and that is deliberate. Inside a container the app always
binds `0.0.0.0`; reach is controlled by the port publish (`127.0.0.1:8080:8080` for loopback-only)
or by joining a network and publishing nothing. A `HOST` variable here would read as a security
control while enforcing nothing — see ARCHITECTURE.md, "Exposure model".

`proxy_headers` is off for the same reason: `allow_from` on an unverified source matches the
socket peer, and letting a caller set `X-Forwarded-For` would hand it the allowlist.
"""

from __future__ import annotations

import argparse
import os
import sys

import structlog
import uvicorn

from . import __version__
from .app import create_app
from .config import load_config
from .errors import ConfigError
from .logging import configure_logging

log = structlog.get_logger(__name__)

DEFAULT_CONFIG_PATH = "/config/config.yml"
CONTAINER_PORT = 8080


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="webhook-doorman", description=__doc__)
    parser.add_argument(
        "-c",
        "--config",
        default=os.environ.get("WEBHOOK_DOORMAN_CONFIG", DEFAULT_CONFIG_PATH),
        help=f"path to config.yml (default: {DEFAULT_CONFIG_PATH}, or $WEBHOOK_DOORMAN_CONFIG)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", CONTAINER_PORT)),
        help=f"port to listen on inside the container (default: {CONTAINER_PORT})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the config and exit without binding a port",
    )
    parser.add_argument("--version", action="version", version=f"webhook-doorman {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        # Print rather than log: a config error happens before anyone is reading JSON logs, and
        # the message is meant for the operator staring at a crash-looping container.
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        print(
            f"config OK: {len(config.sources)} source(s), {len(config.sinks)} sink(s) "
            f"in {args.config}"
        )
        return 0

    app = create_app(config=config)

    log.info("starting", version=__version__, port=args.port, config=args.config)
    uvicorn.run(app, host="0.0.0.0", port=args.port, proxy_headers=False, access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
