#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end test for the policy enrollment flow:
#   Policy → Target Registration → Policy Discovery → Evidence Submission
#
# Prerequisites: podman (or docker), curl, jq, psql, go
#
# Usage:
#   ./scripts/e2e-enrollment-test.sh
#
# The script starts PostgreSQL + NATS containers, builds and runs the gateway,
# then exercises the full enrollment flow. Cleans up on exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Container runtime (podman or docker)
CONTAINER_RT="${CONTAINER_RT:-podman}"

# Container names
PG_CONTAINER="complytime-e2e-pg-$$"
NATS_CONTAINER="complytime-e2e-nats-$$"

# Ports (use high ports to avoid conflicts)
PG_PORT="${PG_PORT:-15432}"
NATS_PORT="${NATS_PORT:-14222}"
GATEWAY_PORT="${GATEWAY_PORT:-18080}"

# Tessera storage
TESSERA_PATH="$(mktemp -d)"

# Gateway PID
GATEWAY_PID=""

# Test state
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo "==> $*"; }
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); TESTS_RUN=$((TESTS_RUN + 1)); echo "  ✓ $*"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); TESTS_RUN=$((TESTS_RUN + 1)); echo "  ✗ $*" >&2; }

cleanup() {
    log "Cleaning up..."
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null && wait "$GATEWAY_PID" 2>/dev/null || true
    $CONTAINER_RT rm -f "$PG_CONTAINER" 2>/dev/null || true
    $CONTAINER_RT rm -f "$NATS_CONTAINER" 2>/dev/null || true
    rm -rf "$TESSERA_PATH"
    rm -f "$PROJECT_DIR/bin/gateway-e2e"
    echo ""
    echo "Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed"
    [ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 max_wait=${2:-30} elapsed=0
    while ! bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$max_wait" ]; then
            echo "Timed out waiting for port $port" >&2
            return 1
        fi
    done
}

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

log "Starting PostgreSQL on port $PG_PORT..."
$CONTAINER_RT run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=complytime \
    -e POSTGRES_PASSWORD=complytime \
    -e POSTGRES_DB=complytime \
    -p "$PG_PORT":5432 \
    docker.io/library/postgres:16 >/dev/null

log "Starting NATS on port $NATS_PORT..."
$CONTAINER_RT run -d --name "$NATS_CONTAINER" \
    -p "$NATS_PORT":4222 \
    docker.io/library/nats:latest >/dev/null

log "Waiting for PostgreSQL..."
wait_for_port "$PG_PORT"

log "Waiting for NATS..."
wait_for_port "$NATS_PORT"

# Give PostgreSQL a moment to accept connections
sleep 2

export POSTGRES_URL="postgres://complytime:complytime@localhost:$PG_PORT/complytime?sslmode=disable"
export NATS_URL="nats://localhost:$NATS_PORT"
export TESSERA_PATH
export PORT="$GATEWAY_PORT"
export LISTEN_HOST="127.0.0.1"
export JWT_ISSUERS=""

# ---------------------------------------------------------------------------
# Build and start gateway
# ---------------------------------------------------------------------------

log "Building gateway..."
cd "$PROJECT_DIR"
go build -o bin/gateway-e2e ./cmd/gateway

log "Starting gateway on port $GATEWAY_PORT..."
./bin/gateway-e2e &
GATEWAY_PID=$!

log "Waiting for gateway..."
wait_for_port "$GATEWAY_PORT"
sleep 1

GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"

# ---------------------------------------------------------------------------
# Test data setup (direct DB insert since JWT not configured)
# ---------------------------------------------------------------------------

log "Step 1: Insert policy with dimensions..."

psql "$POSTGRES_URL" -q -c "
INSERT INTO policies (policy_id, title, version, content,
  technologies, geopolitical, sensitivity,
  evaluation_timeline_start, evaluation_timeline_end, tessera_log_index)
VALUES ('infra-security-baseline', 'Infrastructure Security Baseline', '2.0.0', '',
  '{kubernetes,postgresql}', '{EU}', '{confidential}',
  '2026-04-01T00:00:00Z', '2026-06-30T23:59:59Z', 0)
ON CONFLICT (policy_id) DO UPDATE SET
  technologies = EXCLUDED.technologies,
  geopolitical = EXCLUDED.geopolitical,
  sensitivity = EXCLUDED.sensitivity,
  evaluation_timeline_start = EXCLUDED.evaluation_timeline_start,
  evaluation_timeline_end = EXCLUDED.evaluation_timeline_end,
  tessera_log_index = EXCLUDED.tessera_log_index;
"

# Verify policy stored
POLICY_COUNT=$(psql "$POSTGRES_URL" -t -A -c "SELECT COUNT(*) FROM policies WHERE policy_id = 'infra-security-baseline';")
if [ "$POLICY_COUNT" = "1" ]; then
    pass "Policy stored with dimensions"
else
    fail "Policy not found in database"
fi

# ---------------------------------------------------------------------------

log "Step 2: Register target with dimensions..."

psql "$POSTGRES_URL" -q -c "
INSERT INTO targets (target_id, tessera_log_index, target_name, target_type,
  technologies, geopolitical, sensitivity, users, groups,
  registered_at, registered_by)
VALUES ('prod-cluster', 1, 'Production Kubernetes Cluster', 'kubernetes-cluster',
  '{kubernetes,postgresql}', '{EU}', '{confidential}', '{}', '{}',
  '2026-05-26T10:00:00Z', 'manual-e2e-test')
ON CONFLICT (target_id, tessera_log_index) DO NOTHING;
"

TARGET_COUNT=$(psql "$POSTGRES_URL" -t -A -c "SELECT COUNT(*) FROM targets WHERE target_id = 'prod-cluster';")
if [ "$TARGET_COUNT" = "1" ]; then
    pass "Target registered with dimensions"
else
    fail "Target not found in database"
fi

# ---------------------------------------------------------------------------

log "Step 3: Query policy discovery API..."

DISCOVER_RESP=$(curl -s "$GATEWAY_URL/api/policies/discover?target_id=prod-cluster&timestamp=2026-05-26T10:00:00Z")
DISCOVER_STATUS=$(echo "$DISCOVER_RESP" | jq -r '.target.id // empty')
POLICY_MATCH=$(echo "$DISCOVER_RESP" | jq -r '.applicable_policies[0].policy_id // empty')

if [ "$DISCOVER_STATUS" = "prod-cluster" ]; then
    pass "Discovery API returns target info"
else
    fail "Discovery API missing target info: $DISCOVER_RESP"
fi

if [ "$POLICY_MATCH" = "infra-security-baseline" ]; then
    pass "Discovery API matches policy by dimensions"
else
    fail "Discovery API did not match policy: $DISCOVER_RESP"
fi

# Verify dimension overlap in response
TECH_MATCH=$(echo "$DISCOVER_RESP" | jq -r '.applicable_policies[0].technologies[0] // empty')
if [ "$TECH_MATCH" = "kubernetes" ]; then
    pass "Matched policy has correct technology dimension"
else
    fail "Matched policy missing technology dimension"
fi

# ---------------------------------------------------------------------------

log "Step 4: List registered targets..."

TARGETS_RESP=$(curl -s "$GATEWAY_URL/api/targets")
TARGET_ID=$(echo "$TARGETS_RESP" | jq -r '.[0].target_id // empty')

if [ "$TARGET_ID" = "prod-cluster" ]; then
    pass "Targets list API returns registered target"
else
    fail "Targets list API missing target: $TARGETS_RESP"
fi

# ---------------------------------------------------------------------------

log "Step 5: Query non-existent target (expect 404)..."

NOTFOUND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/api/policies/discover?target_id=nonexistent&timestamp=2026-05-26T10:00:00Z")

if [ "$NOTFOUND_STATUS" = "404" ]; then
    pass "Non-existent target returns 404"
else
    fail "Expected 404, got $NOTFOUND_STATUS"
fi

# ---------------------------------------------------------------------------

log "Step 6: Query with missing target_id (expect 400)..."

BADREQ_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/api/policies/discover")

if [ "$BADREQ_STATUS" = "400" ]; then
    pass "Missing target_id returns 400"
else
    fail "Expected 400, got $BADREQ_STATUS"
fi

# ---------------------------------------------------------------------------

log "Step 7: Query with timestamp outside evaluation window (expect empty)..."

OUTSIDE_RESP=$(curl -s "$GATEWAY_URL/api/policies/discover?target_id=prod-cluster&timestamp=2027-01-01T00:00:00Z")
OUTSIDE_COUNT=$(echo "$OUTSIDE_RESP" | jq '.applicable_policies | length')

if [ "$OUTSIDE_COUNT" = "0" ]; then
    pass "Timestamp outside evaluation window returns no policies"
else
    fail "Expected 0 policies outside window, got $OUTSIDE_COUNT"
fi

# ---------------------------------------------------------------------------

log "Step 8: Register second target with non-matching dimensions..."

psql "$POSTGRES_URL" -q -c "
INSERT INTO targets (target_id, tessera_log_index, target_name, target_type,
  technologies, geopolitical, sensitivity, users, groups,
  registered_at, registered_by)
VALUES ('staging-app', 2, 'Staging Web App', 'web-application',
  '{react,nodejs}', '{US}', '{internal}', '{}', '{}',
  '2026-05-26T10:00:00Z', 'manual-e2e-test')
ON CONFLICT (target_id, tessera_log_index) DO NOTHING;
"

NOMATCH_RESP=$(curl -s "$GATEWAY_URL/api/policies/discover?target_id=staging-app&timestamp=2026-05-26T10:00:00Z")
NOMATCH_COUNT=$(echo "$NOMATCH_RESP" | jq '.applicable_policies | length')

if [ "$NOMATCH_COUNT" = "0" ]; then
    pass "Non-matching dimensions return no applicable policies"
else
    fail "Expected 0 policies for non-matching target, got $NOMATCH_COUNT"
fi

# ---------------------------------------------------------------------------

log "Step 9: Verify database state..."

# Check targets table
TOTAL_TARGETS=$(psql "$POSTGRES_URL" -t -A -c "SELECT COUNT(DISTINCT target_id) FROM targets;")
if [ "$TOTAL_TARGETS" = "2" ]; then
    pass "Two targets registered in database"
else
    fail "Expected 2 targets, got $TOTAL_TARGETS"
fi

# Check policy dimensions stored
POLICY_TECHS=$(psql "$POSTGRES_URL" -t -A -c "SELECT technologies FROM policies WHERE policy_id = 'infra-security-baseline';")
if echo "$POLICY_TECHS" | grep -q "kubernetes"; then
    pass "Policy dimensions persisted in database"
else
    fail "Policy dimensions not found: $POLICY_TECHS"
fi

# ---------------------------------------------------------------------------

echo ""
log "E2E enrollment test complete!"
