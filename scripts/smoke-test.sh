#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test for the ComplyTime Ingest compose stack.
# Verifies: JWT auth → target registration → publisher trust → ingest →
#           Tessera append → witness cosignature → tlog-tiles verification.
#
# Prerequisites:
#   ./scripts/setup-witness.sh
#   cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d
#
# Usage:
#   ./scripts/smoke-test.sh

set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://localhost:8080}"
TESTJWKS="${TESTJWKS_URL:-http://localhost:9090}"
EVIDENCE_FILE="${1:-internal/e2e/testdata/evaluation_log_sample.yaml}"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; exit 1; }
step() { echo ""; echo "Step $1: $2"; }

HEADERS=(-H "X-Forwarded-Email: smoke-test@complytime.dev" \
         -H "X-Forwarded-Preferred-Username: smoke-test" \
         -H "X-Forwarded-Groups: admins,auditors,publishers")

# ── Step 1: Wait for services ──────────────────────────────────────────────

step 1 "Wait for services"

for svc in "$GATEWAY/healthz" "$TESTJWKS/healthz"; do
    for i in $(seq 1 30); do
        if curl -sf "$svc" > /dev/null 2>&1; then
            break
        fi
        if [ "$i" -eq 30 ]; then
            fail "$svc not healthy after 30s"
        fi
        sleep 1
    done
done
pass "All services healthy"

# ── Step 2: Get test JWT ───────────────────────────────────────────────────

step 2 "Get test JWT from JWKS server"

TOKEN=$(curl -sf "$TESTJWKS/token?sub=repo:complytime-labs/complytime-core")
if [ -z "$TOKEN" ]; then
    fail "Empty token from $TESTJWKS/token"
fi
pass "Got JWT (${#TOKEN} chars)"

# ── Step 3: Register target with trusted publisher ────────────────────────

step 3 "Register target with trusted publisher"

EVIDENCE_TARGET=$(python3 -c "
import yaml, sys
with open('$EVIDENCE_FILE') as f:
    d = yaml.safe_load(f)
print(d.get('target',{}).get('id','tgt-test-001'))
" 2>/dev/null || echo "tgt-test-001")

TARGET_REG="metadata:
  type: TargetRegistration
  id: smoke-reg-001
  date: \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
target:
  id: ${EVIDENCE_TARGET}
  name: Smoke Test Target
  type: Software
  trusted-publishers:
    - issuer: http://testjwks:9090
      sub_pattern: \"repo:complytime-labs/*\""

RESPONSE=$(curl -sf -w "\n%{http_code}" \
    -X POST "$GATEWAY/api/ingest" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/x-yaml" \
    "${HEADERS[@]}" \
    -d "$TARGET_REG")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
if [ "$HTTP_CODE" != "202" ]; then
    BODY=$(echo "$RESPONSE" | head -n -1)
    fail "Target registration: expected 202, got $HTTP_CODE: $BODY"
fi
pass "Target registered: $EVIDENCE_TARGET"

# Wait for async processing to populate NATS KV
sleep 3

# ── Step 4: Submit evidence ───────────────────────────────────────────────

step 4 "Submit evidence via POST /api/ingest"

RESPONSE=$(curl -sf -w "\n%{http_code}" \
    -X POST "$GATEWAY/api/ingest" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/x-yaml" \
    "${HEADERS[@]}" \
    -d @"$EVIDENCE_FILE")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" != "202" ]; then
    fail "Expected 202, got $HTTP_CODE: $BODY"
fi

LOG_INDEX=$(echo "$BODY" | grep -o '"log_index":[0-9]*' | cut -d: -f2)
if [ -z "$LOG_INDEX" ]; then
    fail "No log_index in response: $BODY"
fi
pass "Ingested at log_index=$LOG_INDEX"

# ── Step 5: Wait for checkpoint ───────────────────────────────────────────

step 5 "Wait for checkpoint to include entry"

for i in $(seq 1 30); do
    CHECKPOINT=$(curl -sf "${HEADERS[@]}" "$GATEWAY/checkpoint" || true)
    TREE_SIZE=$(echo "$CHECKPOINT" | sed -n '2p')
    if [ -n "$TREE_SIZE" ] && [ "$TREE_SIZE" -gt "$LOG_INDEX" ] 2>/dev/null; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        fail "Checkpoint tree_size ($TREE_SIZE) did not advance past log_index ($LOG_INDEX)"
    fi
    sleep 1
done
pass "Checkpoint tree_size=$TREE_SIZE covers log_index=$LOG_INDEX"

# ── Step 6: Verify witness cosignature ────────────────────────────────────

step 6 "Verify checkpoint has witness cosignature"

SIG_COUNT=$(echo "$CHECKPOINT" | grep -c '^— ' || true)
if [ "$SIG_COUNT" -lt 2 ]; then
    fail "Expected 2+ signatures (log + witness), got $SIG_COUNT"
fi
pass "Checkpoint has $SIG_COUNT signatures (log + $(( SIG_COUNT - 1 )) witness)"

# ── Step 7: Verify witnessed status ───────────────────────────────────────

step 7 "Verify /log/witnessed/$LOG_INDEX"

WITNESSED=$(curl -sf "${HEADERS[@]}" "$GATEWAY/log/witnessed/$LOG_INDEX")
if echo "$WITNESSED" | grep -q '"witnessed":true'; then
    pass "Index $LOG_INDEX is witnessed"
elif echo "$WITNESSED" | grep -q '"witnessed":false'; then
    fail "Index $LOG_INDEX reported as not witnessed: $WITNESSED"
else
    fail "Unexpected response: $WITNESSED"
fi

# ── Step 8: Verify entry readable from tiles ──────────────────────────────

step 8 "Verify entry readable from tlog-tiles API"

TILE_PATH="tile/entries/000.p/1"
TILE_RESP=$(curl -sf -o /dev/null -w "%{http_code}" "${HEADERS[@]}" "$GATEWAY/$TILE_PATH" || true)
if [ "$TILE_RESP" = "200" ]; then
    pass "Entry bundle readable at /$TILE_PATH"
else
    fail "GET /$TILE_PATH returned $TILE_RESP"
fi

# ── Done ──────────────────────────────────────────────────────────────────

echo ""
echo "All smoke tests passed."
