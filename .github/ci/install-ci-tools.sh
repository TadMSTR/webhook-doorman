#!/usr/bin/env bash
# Install the CI tools (pip-audit, build) pinned and hash-checked from uv.lock.
#
# `pip install pip-audit` resolved whatever PyPI served that minute, and publish.yml ran it in
# the job holding `packages: write`, `id-token: write` and `attestations: write`, in reach of
# any install-time script. The `ci-tools` dependency group is locked like everything else and
# Dependabot maintains it, so this installs exactly that closure: `--require-hashes` refuses a
# file whose bytes differ from the lock, and `--no-deps` refuses anything the export left out.
#
# Needs uv on PATH (astral-sh/setup-uv) and the target Python first on PATH (setup-python).
set -euo pipefail

req="${RUNNER_TEMP:-$(mktemp -d)}/ci-tools.txt"
uv export --frozen --only-group ci-tools --no-emit-project --format requirements-txt -o "$req"
python -m pip install --require-hashes --no-deps -r "$req"
