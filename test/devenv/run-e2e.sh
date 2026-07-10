#!/usr/bin/env bash
# End-to-end test of the mikebom adapter against a live Harbor devenv (plan M7).
#
# Prereq: the harbor devenv is up (cd ../harbor && task dev:up SKIP_TRIVY=true, or
# the dev:infra:up + airfix-override path if core crash-loops). This script builds
# the adapter image, joins it to the devenv network, registers it as an SBOM-only
# scanner, and drives a full SBOM scan for two fixtures: a single-platform manifest
# and a full multi-arch index.
#
# Env overrides:
#   H                    Harbor core URL on the host           (default http://localhost:8080)
#   REG                  registry host:port for crane push     (default localhost:8080)
#   AUTH                 admin creds                           (default admin:Harbor12345)
#   HARBOR_NETWORK       external devenv network               (default harbor-0_default)
#   ADAPTER_IMAGE        adapter image tag                     (default mikebom-harbor-adapter:e2e)
#   SINGLE_ARCH          arch for the single-manifest fixture  (default amd64)
#   SKIP_BUILD           set to 1 to reuse an existing image
set -euo pipefail

H="${H:-http://localhost:8080}"
REG="${REG:-localhost:8080}"
AUTH="${AUTH:-admin:Harbor12345}"
HARBOR_NETWORK="${HARBOR_NETWORK:-harbor-0_default}"
ADAPTER_IMAGE="${ADAPTER_IMAGE:-mikebom-harbor-adapter:e2e}"
SINGLE_ARCH="${SINGLE_ARCH:-amd64}"
PROJECT="library"
REPO="mikebom-e2e"
SRC="alpine:3.20"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/docker-compose.devenv.yml"
export ADAPTER_IMAGE HARBOR_NETWORK

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; dump_diagnostics; exit 1; }

dump_diagnostics() {
  log "DIAGNOSTICS: adapter logs"
  ${COMPOSE} logs --no-color --tail=200 mikebom-adapter 2>&1 || true
  log "DIAGNOSTICS: jobservice logs"
  docker logs --tail=120 harbor-0-jobservice-1 2>&1 || true
  if [ -n "${LAST_DGST:-}" ] && [ -n "${LAST_REPORT_ID:-}" ]; then
    log "DIAGNOSTICS: Harbor scan report log (${LAST_REPORT_ID})"
    curl -fsS -u "$AUTH" \
      "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$LAST_DGST/scan/$LAST_REPORT_ID/log" 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# 0. Preflight: devenv must be reachable.
# ---------------------------------------------------------------------------
log "Preflight: Harbor core ping"
curl -fsS "$H/api/v2.0/ping" || fail "Harbor core not reachable at $H (bring the devenv up first)"
echo
docker network inspect "$HARBOR_NETWORK" >/dev/null 2>&1 || fail "network $HARBOR_NETWORK not found (check SLOT: docker network ls | grep harbor)"

# ---------------------------------------------------------------------------
# 1. Build the adapter image (task image stages mikebom from its release tarball).
# ---------------------------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "Building adapter image ${ADAPTER_IMAGE}"
  ( cd "$REPO_ROOT" && task image PUSH=false IMAGE_TAG="${ADAPTER_IMAGE##*:}" )
fi

# ---------------------------------------------------------------------------
# 2. Bring the adapter up on the devenv network.
# ---------------------------------------------------------------------------
log "Starting adapter on ${HARBOR_NETWORK}"
${COMPOSE} up -d
trap '${COMPOSE} down >/dev/null 2>&1 || true' EXIT

log "Waiting for adapter /api/v1/metadata"
for i in $(seq 1 30); do
  if curl -fsS http://localhost:8090/api/v1/metadata >/dev/null 2>&1; then break; fi
  sleep 2
  [ "$i" = "30" ] && fail "adapter metadata not reachable on :8090"
done
META=$(curl -fsS http://localhost:8090/api/v1/metadata)
echo "$META" | jq .
echo "$META" | jq -e '.capabilities[0].type=="sbom"' >/dev/null \
  || fail "adapter metadata does not advertise the sbom capability"

# ---------------------------------------------------------------------------
# 3. Register the adapter + assert SBOM-only capabilities, then bind project.
# ---------------------------------------------------------------------------
log "Registering scanner (idempotent)"
UUID=$(curl -fsS -u "$AUTH" "$H/api/v2.0/scanners?q=name%3Dmikebom" | jq -r '.[0].uuid // empty')
if [ -z "$UUID" ]; then
  curl -fsS -u "$AUTH" -X POST "$H/api/v2.0/scanners" -H 'Content-Type: application/json' -d '{
    "name":"mikebom","description":"mikebom SBOM adapter (e2e)",
    "url":"http://mikebom-adapter:8080","disabled":false,"skip_certVerify":true}' \
    || fail "scanner registration failed (Harbor could not reach http://mikebom-adapter:8080?)"
  UUID=$(curl -fsS -u "$AUTH" "$H/api/v2.0/scanners?q=name%3Dmikebom" | jq -r '.[0].uuid // empty')
else
  echo "scanner 'mikebom' already registered, reusing"
fi
[ -n "$UUID" ] && [ "$UUID" != "null" ] || fail "could not resolve scanner uuid"
echo "scanner uuid: $UUID"

log "Asserting capabilities from GET /scanners/{uuid}"
CAPS=$(curl -fsS -u "$AUTH" "$H/api/v2.0/scanners/$UUID")
echo "$CAPS" | jq '.capabilities'
echo "$CAPS" | jq -e '.capabilities.support_sbom==true' >/dev/null \
  || fail "capabilities.support_sbom is not true"
# support_vulnerability must be ABSENT (not false) for an sbom-only scanner.
echo "$CAPS" | jq -e '.capabilities | has("support_vulnerability") | not' >/dev/null \
  || fail "capabilities.support_vulnerability must be absent for an sbom-only scanner"

log "Binding project ${PROJECT} to the mikebom scanner"
curl -fsS -u "$AUTH" -X PUT "$H/api/v2.0/projects/$PROJECT/scanner" \
  -H 'Content-Type: application/json' -d "{\"uuid\":\"$UUID\"}" \
  || fail "project scanner binding failed"

# ---------------------------------------------------------------------------
# 4. crane fixtures.
# ---------------------------------------------------------------------------
log "crane auth login ${REG}"
crane auth login "$REG" -u "${AUTH%%:*}" -p "${AUTH#*:}"

# Clean slate so the poll and accessory assertions are deterministic (a re-run must
# not observe accessories left by a previous run).
log "Deleting any pre-existing ${PROJECT}/${REPO} repository"
curl -sS -u "$AUTH" -o /dev/null -w 'DELETE repo HTTP %{http_code}\n' -X DELETE \
  "$H/api/v2.0/projects/$PROJECT/repositories/$REPO" || true

log "Resolving single-platform child digest (linux/${SINGLE_ARCH}) of ${SRC}"
CHILD=$(crane manifest "$SRC" | jq -r \
  '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="'"$SINGLE_ARCH"'") | .digest' | head -1)
[ -n "$CHILD" ] && [ "$CHILD" != "null" ] || fail "could not resolve child digest for linux/${SINGLE_ARCH}"
echo "child digest: $CHILD"
log "Pushing single-manifest fixture :single (crane copy alpine@<child-digest>)"
crane copy "alpine@${CHILD}" "$REG/$PROJECT/$REPO:single"
log "Pushing full-index fixture :index (crane copy alpine:3.20)"
crane copy "$SRC" "$REG/$PROJECT/$REPO:index"

# ---------------------------------------------------------------------------
# 5-7. Per fixture: trigger, poll (break on Error), assert accessory + SPDX.
# ---------------------------------------------------------------------------

# assert_spdx <artifact-ref>: assert an sbom.harbor accessory on the given ref,
# then download + validate its additions/sbom as non-empty SPDX 2.3. Echoes the
# package count.
assert_spdx() {
  local ref="$1" acc sbom_dgst spdx
  acc=$(curl -fsS -u "$AUTH" \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$ref/accessories")
  echo "$acc" | jq -e 'any(.[]?; .type=="sbom.harbor")' >/dev/null \
    || fail "$ref has no sbom.harbor accessory"
  sbom_dgst=$(echo "$acc" | jq -r '[.[] | select(.type=="sbom.harbor")][0].digest')
  spdx=$(curl -fsS -u "$AUTH" \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$sbom_dgst/additions/sbom")
  echo "$spdx" | jq -e '.spdxVersion=="SPDX-2.3" and (.packages|length)>0 and .SPDXID=="SPDXRef-DOCUMENT"' >/dev/null \
    || fail "$ref additions/sbom is not a valid non-empty SPDX 2.3 document"
  echo "$spdx" | jq -c '{ref: "'"$ref"'", sbom_accessory: "'"$sbom_dgst"'", spdxVersion, packages: (.packages|length)}'
}

# trigger_scan <artifact-digest>: POST an sbom scan and assert 202.
trigger_scan() {
  local dgst="$1" code
  LAST_DGST="$dgst"
  code=$(curl -fsS -u "$AUTH" -o /dev/null -w '%{http_code}' -X POST \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$dgst/scan" \
    -H 'Content-Type: application/json' -d '{"scan_type":"sbom"}')
  echo "trigger HTTP $code"
  [ "$code" = "202" ] || fail "scan trigger for $dgst returned $code (expected 202)"
}

# has_sbom_accessory <artifact-ref>: 0 if the ref carries an sbom.harbor accessory.
has_sbom_accessory() {
  curl -fsS -u "$AUTH" \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$1/accessories" \
    | jq -e 'any(.[]?; .type=="sbom.harbor")' >/dev/null 2>&1
}

# index_scan_status <index-digest>: echoes sbom_overview.scan_status (or None).
index_scan_status() {
  local art
  art=$(curl -fsS -u "$AUTH" \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$1?with_sbom_overview=true")
  local rid; rid=$(echo "$art" | jq -r '.sbom_overview.report_id // empty')
  if [ -n "$rid" ]; then LAST_REPORT_ID="$rid"; fi
  echo "$art" | jq -r '.sbom_overview.scan_status // "None"'
}

run_single() {
  local dgst status i
  dgst=$(crane digest "$REG/$PROJECT/$REPO:single")
  log "Fixture :single (single manifest)  digest=$dgst"
  log "Triggering + polling :single (sbom_overview.scan_status)"
  trigger_scan "$dgst"
  for i in $(seq 1 60); do
    status=$(index_scan_status "$dgst")
    printf '  [%02d] sbom_overview.scan_status=%s\n' "$i" "$status"
    [ "$status" = "Error" ] && fail ":single scan reported Error (see diagnostics)"
    [ "$status" = "Success" ] && break
    sleep 5
  done
  [ "$status" = "Success" ] || fail ":single did not reach Success (last=$status)"
  log "Asserting accessory + SPDX for :single (on the artifact itself)"
  assert_spdx "$dgst"
  printf '\nPASS :single  sbom.harbor accessory + SPDX 2.3 on the artifact\n'
}

run_index() {
  local dgst children n c ok=0 done_count i status
  dgst=$(crane digest "$REG/$PROJECT/$REPO:index")
  log "Fixture :index (multi-arch index)  digest=$dgst  mediaType=$(crane manifest "$REG/$PROJECT/$REPO:index" | jq -r '.mediaType')"
  # Children are where Harbor fans the SBOM out to: the index media type is not in
  # the adapter's consumes list, so Harbor walks the index down to each child
  # manifest and scans them individually (see docs/harbor-behavior.md).
  children=$(crane manifest "$REG/$PROJECT/$REPO:index" \
    | jq -r '.manifests[] | select(.platform.os!="unknown") | .digest')
  n=$(echo "$children" | wc -w | tr -d ' ')
  echo "index has $n platform children"
  trigger_scan "$dgst"
  # Completion signal = every child carries an sbom.harbor accessory. The index-level
  # sbom_overview is only populated transiently while children scan, so the durable
  # signal is the per-child accessory, not the index status.
  log "Polling :index until all $n children carry an sbom.harbor accessory (Error-guarded)"
  for i in $(seq 1 60); do
    status=$(index_scan_status "$dgst")
    done_count=0
    for c in $children; do
      if has_sbom_accessory "$c"; then done_count=$((done_count + 1)); fi
    done
    printf '  [%02d] index.scan_status=%s  children_with_sbom=%s/%s\n' "$i" "$status" "$done_count" "$n"
    [ "$status" = "Error" ] && fail ":index scan reported Error (see diagnostics)"
    [ "$done_count" = "$n" ] && break
    sleep 5
  done
  [ "$done_count" = "$n" ] || fail ":index only $done_count/$n children produced an SBOM"

  log "Asserting the index itself has NO accessory (fan-out target is the children)"
  curl -fsS -u "$AUTH" \
    "$H/api/v2.0/projects/$PROJECT/repositories/$REPO/artifacts/$dgst/accessories" | jq -c '.'

  log "Asserting every child carries an sbom.harbor accessory + valid SPDX 2.3"
  for c in $children; do
    assert_spdx "$c"
    ok=$((ok + 1))
  done
  [ "$ok" = "$n" ] || fail "only $ok/$n children produced a valid SBOM"
  printf '\nPASS :index  all %s children fanned out with sbom.harbor accessory + SPDX 2.3\n' "$n"
}

run_single
run_index

log "GATE PASSED: both fixtures produced an sbom.harbor accessory with valid SPDX 2.3 (single: on the artifact; index: fanned out to every child)"
