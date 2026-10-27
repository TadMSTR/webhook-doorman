#!/usr/bin/env bash
#
# Every gate that runs against a built image, in one place.
#
# This script is called by BOTH `ci.yml` (on every PR) and `publish.yml` (before the push to
# GHCR). That is the point of it existing: when these gates lived only in ci.yml, the publish
# path pushed an artefact that nothing had checked, and any gate added to one path would
# silently not apply to the other. A drift between "what a PR must pass" and "what we agree to
# publish" is the failure this file is shaped to prevent.
#
# Usage: .github/ci/verify-image.sh <image-tag>
# Run from the repository root — it reads config.example.yml and .github/ci/smoke-config.yml.

set -euo pipefail

IMAGE="${1:?usage: verify-image.sh <image-tag>}"
WORK="$(mktemp -d)"

# Every scratch container this script creates is named with the PID suffix, and all three are
# removed unconditionally on exit. Naming matters: a bare name like "probe" is host-global in
# Docker, so a collision would target something that is not ours. Removing them in the trap
# rather than only inline matters too — `set -e` aborts on the first failing gate, and an
# inline-only `docker rm` leaks a container on exactly the runs that failed.
cleanup() {
  docker rm -f "wd-contents-$$" "wd-audit-$$" "wd-smoke-$$" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "::error::$*"; exit 1; }

echo "=== verifying $IMAGE ==="

# --- 1. Image contents ------------------------------------------------------------------------
#
# The published image is public. A .dockerignore entry that stops matching does so silently, so
# this asserts on the actual filesystem of the built image rather than trusting the ignore file.
#
# Vendored paths are excluded first: the base image ships a CA bundle full of .pem files and
# several dependencies vendor their own tests/ directory. Matching those would make the check
# noisy enough to be disabled, which is worse than not having it.
echo "--- image contents ---"
docker create --name "wd-contents-$$" "$IMAGE" >/dev/null
docker export "wd-contents-$$" > "$WORK/image.tar"
docker rm "wd-contents-$$" >/dev/null
tar -tf "$WORK/image.tar" > "$WORK/all.txt"

grep -vE '^(etc/ssl/|usr/(lib|share|local)/|opt/venv/lib/python[0-9.]+/site-packages/[^w])' \
  "$WORK/all.txt" > "$WORK/own.txt"

# A control on the filter itself. If the exclusion regex ever widens to the point of matching
# everything, every assertion below becomes vacuous and still green — the gate would report
# success precisely because it was looking at nothing. Absence-only assertions cannot detect
# that; only a floor on what remains can.
own_count=$(wc -l < "$WORK/own.txt")
[ "$own_count" -ge 50 ] || fail "only $own_count non-vendored paths survived the filter — the exclusion regex is too broad and the contents gate is vacuous"

if grep -Ei '(^|/)(\.env(\..*)?|config\.ya?ml|secrets\.ya?ml|.*\.key|.*\.pem)$' "$WORK/own.txt"; then
  fail "a secret or config file reached the published image"
fi
if grep -E '(^|/)tests/' "$WORK/own.txt"; then
  fail "test fixtures reached the published image"
fi
# The build context should never have produced a copy of the source tree or the repo root in
# the final stage.
if grep -E '^(src/|build/|\.git/)' "$WORK/own.txt"; then
  fail "build context leaked into the final stage"
fi
echo "image contents clean ($(wc -l < "$WORK/all.txt") entries, $own_count non-vendored)"

# No pip anywhere in the merged filesystem (vikunja#1033). Read from all.txt, not own.txt: both
# copies live under paths the vendored filter above removes. The python3 count is the control.
# A listing that had lost /usr/local would show no pip and prove nothing.
py_count=$(grep -cE '^usr/local/bin/python3' "$WORK/all.txt" || true)
[ "$py_count" -ge 1 ] || fail "no usr/local/bin/python3 in the image listing — the pip check below would be vacuous"
# Into a file, not `grep | head`: under pipefail, head closing the pipe kills grep with SIGPIPE,
# and the `if` reads 141 as "no match". That shipped green against the 0.6.0 image in a draft.
grep -E '(^|/)site-packages/pip(/|-[0-9][^/]*\.dist-info/)|^usr/local/bin/pip' \
  "$WORK/all.txt" > "$WORK/pip.txt" || true
if [ -s "$WORK/pip.txt" ]; then
  head -5 "$WORK/pip.txt"
  fail "pip reached the runtime image ($(wc -l < "$WORK/pip.txt") paths)"
fi
if docker run --rm --entrypoint python "$IMAGE" -c 'import pip' >/dev/null 2>&1; then
  fail "'import pip' succeeds inside the image"
fi
echo "pip absent (filesystem and import)"

# --- 2. Runtime user --------------------------------------------------------------------------
echo "--- runtime uid ---"
uid=$(docker run --rm --entrypoint id "$IMAGE" -u)
echo "runtime uid: $uid"
[ "$uid" != "0" ] || fail "image runs as root"
[ "$uid" = "10001" ] || fail "expected uid 10001, got $uid"

# --- 3. Entry point and config validation -----------------------------------------------------
#
# Flagship requires the config-validation entry point to be exercised against the image as well
# as the wheel. `--check` is what an adopter runs before a deploy; if it is broken in the image
# they find out at deploy time.
echo "--- entry point ---"
docker run --rm --entrypoint webhook-doorman "$IMAGE" --version
docker run --rm -v "$PWD/config.example.yml:/config/config.yml:ro" "$IMAGE" --check

# --- 4. Dependency audit of the tree that actually shipped ------------------------------------
#
# vikunja#670. The repo's separate `audit` job reads declared *ranges*, so pip-audit re-resolves
# and reports on a tree that is deployed nowhere; the same ticket recorded a case where that
# read clean while the real venv held 11 CVEs across 4 packages. This step audits the versions
# that are actually installed in the artefact about to ship.
#
# `--path` rather than `-r` is load-bearing, and not interchangeable with it. `pip-audit -r`
# runs a pip dry-run resolution *regardless of --no-deps* (verified against pip-audit 2.10.1),
# so it re-derives versions instead of reading them — which is the very bug this step exists to
# close. `--path` enumerates installed dist-info metadata and resolves nothing.
#
# webhook_doorman's own dist-info is removed from the extracted copy first. It is not published
# to PyPI, so `--strict` cannot audit it and would fail the whole gate on the one package that
# is built from the source in this repo. Removing it keeps `--strict` meaningful for every
# dependency, which is the set actually at risk.
echo "--- dependency audit (shipped tree) ---"
docker create --name "wd-audit-$$" "$IMAGE" >/dev/null
docker cp "wd-audit-$$:/opt/venv/lib" "$WORK/venvlib" >/dev/null
docker rm "wd-audit-$$" >/dev/null

sp=$(find "$WORK/venvlib" -maxdepth 2 -name site-packages | head -1)
[ -n "$sp" ] || fail "could not locate site-packages inside the image"
rm -rf "$sp"/webhook_doorman "$sp"/webhook_doorman-*.dist-info

# A floor, for the same reason as the contents control above: an extraction that silently
# produced an empty or near-empty directory would audit nothing and exit 0. "No vulnerabilities
# found in 0 packages" and "no vulnerabilities found in 47 packages" are the same output.
pkgs=$(find "$sp" -maxdepth 1 -name '*.dist-info' | wc -l)
echo "auditing $pkgs installed packages from the image"
[ "$pkgs" -ge 20 ] || fail "only $pkgs packages found in the image — extraction is wrong and this gate would be vacuous"

pip-audit --strict --path "$sp"

# --- 4b. Image scan: OS packages and everything pip-audit cannot see --------------------------
#
# pip-audit reads only the venv's dist-info. It is blind to Debian packages and to vendored
# copies, such as pip's own certifi and urllib3. On 0.6.0 this step failed (6 fixable
# HIGH/CRITICAL) while the audit above passed on all but one of them (vikunja#1033).
#
# HIGH/CRITICAL with a fix available, and no .trivyignore: an unfixable finding gives a red build
# with no action behind it, which is how a gate gets bypassed rather than fixed.
#
# The scanner's reference comes from .github/ci/trivy/Dockerfile, so Dependabot bumps it. It
# scans a `docker save` tarball mounted read-only, rather than the daemon through a mounted
# socket. The socket would give a third-party image root on the runner.
echo "--- image scan (trivy) ---"
TRIVY=$(sed -n 's/^FROM \([^ ]*\).*/\1/p' .github/ci/trivy/Dockerfile)
[[ "$TRIVY" == *@sha256:* ]] || fail "trivy reference '$TRIVY' is not digest-pinned"
docker save "$IMAGE" -o "$WORK/image-save.tar"
docker run --rm -v "$WORK:/work:ro" "$TRIVY" image --quiet --scanners vuln \
  --input /work/image-save.tar --list-all-pkgs --format json > "$WORK/trivy.json"

# The floor, again: a scan that recognised no packages finds nothing and would pass. Measured
# 2026-10-27: 87 Debian and 49 Python packages without pip, and 87 and 85 on 0.6.0, where
# pip's vendored copies count too.
python3 - "$WORK/trivy.json" <<'PY' || fail "trivy gate failed"
import json, sys
d = json.load(open(sys.argv[1]))
os_n = py_n = 0
bad = []
for r in d.get("Results") or []:
    n = len(r.get("Packages") or [])
    if r.get("Class") == "os-pkgs":
        os_n += n
    elif r.get("Type") == "python-pkg":
        py_n += n
    for v in r.get("Vulnerabilities") or []:
        if v.get("Severity") in ("HIGH", "CRITICAL") and v.get("FixedVersion"):
            bad.append(f'{v["Severity"]:8} {v["PkgName"]} {v["InstalledVersion"]} -> '
                       f'{v["FixedVersion"]} {v["VulnerabilityID"]} {v.get("PkgPath", "")}')
print(f"trivy recognised {os_n} OS and {py_n} Python packages")
if os_n < 40 or py_n < 20:
    sys.exit("too few packages recognised; the scan is vacuous")
for b in bad:
    print("::error::" + b)
if bad:
    sys.exit(f"{len(bad)} fixable HIGH/CRITICAL finding(s)")
print("no fixable HIGH/CRITICAL findings")
PY

# --- 5. Service contract ----------------------------------------------------------------------
#
# Flagship requires the smoke test to assert the service *contract*, not liveness. For a
# fail-closed webhook router the contract is verification, and the ACCEPT case is the one that
# carries the weight: without it, a build in which verification rejects everything passes this
# test identically to one that works. Rejection-only assertions cannot tell a working router
# from a brick.
echo "--- service contract ---"
SECRET="ci-smoke-secret-not-used-anywhere"

# Port 0 lets Docker assign a free port, which is then read back. A hardcoded port can already
# be held by something else on the runner, in which case every curl below would describe a
# different service and pass or fail for reasons unrelated to this image.
CONTAINER="wd-smoke-$$"
docker run -d --name "$CONTAINER" -p 127.0.0.1:0:8080 \
  -v "$PWD/.github/ci/smoke-config.yml:/config/config.yml:ro" \
  -e SMOKE_SECRET="$SECRET" \
  -e SMOKE_SINK_URL="http://127.0.0.1:9/sink" \
  "$IMAGE" >/dev/null

PORT=$(docker port "$CONTAINER" 8080/tcp | head -1 | sed 's/.*://')
[ -n "$PORT" ] || fail "could not determine the mapped port"
BASE="http://127.0.0.1:$PORT"
echo "container $CONTAINER on $BASE"

for _ in $(seq 1 30); do
  curl -sf -o /dev/null "$BASE/health" && break
  sleep 1
done

# 5a. /health answers without credentials, and identifies itself. A bare 200 could come from
# anything holding the port; the version field could not.
health=$(curl -s "$BASE/health") || fail "/health did not answer"
echo "$health" | grep -q '"status":"ok"' || fail "/health did not report ok: $health"
echo "$health" | grep -q '"version"' || fail "/health carried no version — is this webhook-doorman? got: $health"
echo "health: ok"

BODY='{"event":"smoke","message":"ci contract test"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# 5b. No signature -> refused.
c=$(code -X POST -H 'Content-Type: application/json' -d "$BODY" "$BASE/webhook/smoke")
[ "$c" = "401" ] || fail "unsigned request returned $c, expected 401"
echo "unsigned: 401"

# 5c. Wrong signature -> refused. Distinct from 5b: 5b tests the absent-header path, this tests
# the comparison itself. A router that only checked for the header's presence passes 5b.
c=$(code -X POST -H 'Content-Type: application/json' \
  -H "X-Smoke-Signature: sha256=0000000000000000000000000000000000000000000000000000000000000000" \
  -d "$BODY" "$BASE/webhook/smoke")
[ "$c" = "401" ] || fail "wrongly-signed request returned $c, expected 401"
echo "wrong signature: 401"

# 5d. Correct signature -> accepted. The control for 5b and 5c, and the assertion that stops an
# always-reject build passing. The body is checked too: only this service answers "accepted".
resp=$(curl -s -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
  -H "X-Smoke-Signature: sha256=$SIG" -d "$BODY" "$BASE/webhook/smoke")
c=$(echo "$resp" | tail -1)
payload=$(echo "$resp" | head -n -1)
[ "$c" = "200" ] || fail "correctly-signed request returned $c, expected 200 (body: $payload)"
echo "$payload" | grep -q '"status":"accepted"' || fail "correctly-signed request was not accepted: $payload"
echo "correct signature: 200 accepted"

echo "=== $IMAGE passed all gates ==="
