# syntax=docker/dockerfile:1

# --- build ------------------------------------------------------------------------------------
# The builder produces a self-contained virtualenv. Nothing from this stage reaches the final
# image except /opt/venv, so build tooling, the source tree and pip's cache stay out of the
# published layers.
FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

# README and LICENSE are referenced by pyproject metadata; the build fails without them.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/venv && /opt/venv/bin/pip install .

# --- runtime ----------------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WEBHOOK_DOORMAN_CONFIG=/config/config.yml

# A fixed, documented UID rather than a floating one. The data directory on the host has to be
# owned by this UID for SQLite to create its file and the -wal/-shm siblings beside it, and an
# operator cannot chown to a UID that changes between builds.
RUN groupadd --system --gid 10001 doorman \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --shell /usr/sbin/nologin doorman \
 && mkdir -p /data /config \
 && chown -R doorman:doorman /data

COPY --from=builder /opt/venv /opt/venv

USER doorman
WORKDIR /data
VOLUME ["/data"]

# The container always binds 0.0.0.0. That is not a setting: inside a container the bind address
# is not what decides reach -- the port publish and network membership are. A HOST variable here
# would read as a control while enforcing nothing. See ARCHITECTURE.md, "Exposure model".
EXPOSE 8080

# stdlib only. Adding curl to a slim image for a healthcheck is a package and a CVE feed for
# something Python already does.
#
# The `except` is not defensive padding. Since 0.1.1 `/health` answers 503 when the router has
# no enabled source or cannot reach its store, and `urlopen` raises `HTTPError` on a 503 rather
# than returning a response to compare — so without this, a designed unhealthy state exits
# non-zero via an uncaught traceback. Same verdict, arrived at by accident and logged as noise.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request as u\ntry:\n    sys.exit(0 if u.urlopen('http://127.0.0.1:8080/health', timeout=3).status == 200 else 1)\nexcept Exception:\n    sys.exit(1)"]

ENTRYPOINT ["webhook-doorman"]
