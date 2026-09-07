# syntax=docker/dockerfile:1

# --- build ------------------------------------------------------------------------------------
# The builder produces a self-contained virtualenv. Nothing from this stage reaches the final
# image except /opt/venv, so build tooling, the source tree and pip's cache stay out of the
# published layers.
#
# Pinned by tag AND digest, for the same reason the uv stage below is: a mutable tag is an
# unpinned dependency wearing a version number. Docker Hub can repoint `3.13-slim` at new
# content at any time, so without the digest two builds of an unchanged Dockerfile can pull
# different base layers with nothing in git recording it — which would undercut the
# reproducibility the lockfile and the audit gates are there to provide.
#
# Dependabot's `docker` ecosystem does NOT close this on its own while tag-pinned: it opens a
# PR when the version tag moves (3.13 -> 3.14), not when content changes behind an unchanged
# tag. Once digest-pinned it tracks digest bumps, so this costs no unmanaged maintenance.
#
# This digest is an OCI image index covering linux/amd64 and linux/arm64 (verified), so the
# multi-arch publish still resolves per-platform. Do not replace it with a single-platform
# digest — that would break the arm64 leg.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

# uv is here only to turn uv.lock into a hash-pinned requirements file. Pinned by digest as
# well as tag, because a mutable tag in a build stage is an unpinned dependency wearing a
# version number.
COPY --from=ghcr.io/astral-sh/uv:0.12.10@sha256:2bb3ebca0a796a155094a27773d290c4b074572e6107f171d88d086682fd2500 /uv /usr/local/bin/uv

# README and LICENSE are referenced by pyproject metadata; the build fails without them.
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

# This install resolves NOTHING. It previously ran `pip install '.[otel]'`, which re-resolved
# every dependency at build time — so the published image's tree was decided by whatever PyPI
# served that minute, and matched no audited set anywhere. That is vikunja#670: the CI audit and
# the image build were two separate resolves, and only the image shipped.
#
# `uv export` reads the committed lock and emits exact versions with hashes; `--require-hashes`
# makes pip refuse anything whose artefact does not match. `--no-deps` on both installs stops
# pip re-deriving a dependency graph the lock already fixed.
#
# `[otel]` is included in the image so enabling tracing is one environment variable rather than
# a derived image. An adopter who never sets OTEL_EXPORTER_OTLP_ENDPOINT pays image size and
# nothing else — tracing.py imports none of it unless that variable is set.
RUN uv export --frozen --no-dev --extra otel --no-emit-project \
        --format requirements.txt -o /tmp/requirements.txt \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r /tmp/requirements.txt \
 && /opt/venv/bin/pip install --no-deps .

# --- runtime ----------------------------------------------------------------------------------
# Same digest as the builder stage above, and it must stay that way — see the reasoning there.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS runtime

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
