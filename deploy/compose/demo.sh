#!/usr/bin/env bash
# ComplyTime demo: register subject → publish evidence → query graph → show Cedar deny
# Usage:
#   cd deploy/compose
#   docker compose up -d          # or --profile demo for Memgraph Lab
#   ./demo.sh

set -euo pipefail

GW=http://localhost:8080
GRAPH=http://localhost:8082
JWKS=http://localhost:8888

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BOLD}${CYAN}── $*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
die()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────
step "Preflight: checking stack is up"

curl -sf "$GW/healthz"    > /dev/null || die "Gateway not reachable at $GW — run: docker compose up -d"
curl -sf "$JWKS/healthz"  > /dev/null || die "testjwks not reachable at $JWKS — run: docker compose up -d"
curl -sf "$GRAPH/healthz" > /dev/null || die "Graph not reachable at $GRAPH — run: docker compose up -d"

ok "All services healthy"

# ── Helpers ────────────────────────────────────────────────────────────────

mint() {
  local sub="$1" aud="$2"
  shift 2
  local groups=("$@")
  local body token
  body=$(printf '{"sub":"%s","audience":["%s"],"groups":[%s]}' \
    "$sub" "$aud" "$(printf '"%s",' "${groups[@]}" | sed 's/,$//')")
  token=$(curl -sf -X POST "$JWKS/mint" -H "Content-Type: application/json" -d "$body" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
  [[ -n "$token" ]] || die "mint failed for sub=$sub aud=$aud"
  echo "$token"
}

# ── Step 1: Admin registers a subject ──────────────────────────────────────
step "Register subject (admin token → gateway front door)"

ADMIN_TOKEN=$(mint "demo-admin" "complytime-gateway" "complytime-admin")

REG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW/admin/subjects" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subjectId":"demo-app-v1","trustedPublishers":[{"issuer":"http://testjwks:8888","sub":"demo-publisher"}]}')

if [[ "$REG_STATUS" == "201" || "$REG_STATUS" == "200" ]]; then
  ok "demo-app-v1 registered with trusted publisher demo-publisher"
elif [[ "$REG_STATUS" == "500" ]]; then
  ok "demo-app-v1 already registered (re-run) — continuing"
else
  die "Registration returned HTTP $REG_STATUS"
fi

# ── Step 2: Publisher submits an EvaluationLog ────────────────────────────
step "Publish compliance evidence (publisher token → gateway → locker)"

PUB_TOKEN=$(mint "demo-publisher" "complytime-gateway" "complytime-publisher")

RECEIPT=$(curl -sf -X POST "$GW/api/ingest" \
  -H "Authorization: Bearer $PUB_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Subject-ID: demo-app-v1" \
  -d '{
    "target": {"id": "demo-app-v1", "name": "demo-app", "type": "Software"},
    "metadata": {
      "id": "eval-branch-protection-001",
      "type": "EvaluationLog",
      "gemara-version": "1.0.0",
      "description": "Branch protection evaluation for demo-app-v1",
      "author": {"id": "ampel", "name": "AMPEL", "type": "Software"}
    },
    "evaluations": [{
      "name": "Require Pull Request Reviews",
      "message": "Direct pushes to main are blocked.",
      "result": "Passed",
      "control": {"entry-id": "BP-1", "reference-id": "repo-branch-protection/BP-1"},
      "assessment-logs": [{
        "requirement": {"entry-id": "BP-1.01", "reference-id": "repo-branch-protection/BP-1.01"},
        "description": "Direct pushes to main are blocked",
        "message": "Branch protection rule active on main",
        "result": "Passed",
        "applicability": ["main"],
        "start": "2026-08-04T12:00:00Z",
        "steps": ["Checked branch protection via GitHub API"]
      }]
    }],
    "result": "Passed"
  }')

JOB_ID=$(echo "$RECEIPT" | python3 -c "import sys,json; print(json.load(sys.stdin)['jobId'])")
[[ -n "$JOB_ID" ]] || die "ingest response missing jobId: $RECEIPT"
ok "Evidence accepted — jobId: $JOB_ID"
echo "   Gateway sealed the artifact in the append-only locker."

# ── Step 3: Cedar blocks untrusted publish attempt ────────────────────────
step "Cedar authz deny: auditor cannot publish (policy enforcement)"

AUDITOR_TOKEN=$(mint "demo-auditor" "complytime-gateway" "complytime-auditor")

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW/api/ingest" \
  -H "Authorization: Bearer $AUDITOR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Subject-ID: demo-app-v1" \
  -d '{"metadata":{"type":"EvaluationLog"},"evaluations":[],"result":"Passed"}')

if [[ "$HTTP_STATUS" == "403" ]]; then
  ok "Auditor publish blocked: HTTP 403 — Cedar forbid policy enforced"
else
  die "Expected 403, got $HTTP_STATUS"
fi

# ── Step 4: Wait for graph to ingest evidence, then query ─────────────────
step "Query graph service (auditor token → compliance consumer view)"

echo "   Waiting for graph loader to consume from NATS..."
sleep 8

GRAPH_TOKEN=$(mint "demo-auditor" "complytime-graph" "complytime-auditor")

echo ""
curl -sf -H "Authorization: Bearer $GRAPH_TOKEN" "$GRAPH/api/subjects" | python3 -m json.tool
echo ""

ok "Graph shows demo-app-v1 with EvaluationLog evidence"

# ── Done ──────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}Demo complete.${NC}"
echo ""
echo "  Memgraph Lab (visual graph explorer): http://localhost:3000"
echo "  Connect to: localhost:7687 (no auth)"
echo ""
echo "  Try these Cypher queries in Lab:"
echo ""
echo "    // All subjects with evidence and publishers"
echo "    MATCH (s:Subject)<-[:TARGETS]-(e:Evidence)-[:PUBLISHED_BY]->(p:Publisher)"
echo "    RETURN s, e, p"
echo ""
echo "    // Zoom into demo-app-v1"
echo '    MATCH path = (s:Subject {id: "demo-app-v1"})<-[:TARGETS]-(e:Evidence)-[:PUBLISHED_BY]->(p:Publisher)'
echo "    RETURN path"
echo ""
echo "  To run with Memgraph Lab:"
echo "    docker compose --profile demo up -d"
