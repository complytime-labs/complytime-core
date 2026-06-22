# Testing Strategy

**Status:** Accepted
**Date:** 2026-06-19

## Decision

Five test layers, each answering a different question. Every layer must be maintained — gaps in any layer are treated as bugs.

| Layer | What it answers | Output |
|:--|:--|:--|
| **Unit** | Does this function work? | pass/fail |
| **Contract** | Will downstream subscribers break? | pass/fail |
| **BDD E2E** | Does the full workflow work? | Ginkgo report |
| **Security evaluation** | Do the security properties hold? | Gemara EvaluationLog + SARIF |
| **Smoke** | Does the deployed stack work? | pass/fail per step |

## Test Layers

### Unit Tests

**Location:** `*_test.go` in each package, no build tags.

Tests individual functions, store operations, and parsers. NATS KV stores use an embedded `nats-server/v2/server` — no external infrastructure.

**Covers:**
- NATS KV publisher trust store: insert, get, remove, upsert, multi-target
- NATS KV target store: insert, get, list, upsert
- Auth session injection, JWT verification
- Evidence parsing, artifact type detection
- Ingest worker message handling (ack/nak/term outcomes)
- Fail-closed behavior: NATS KV unavailable → rejection

**Run:** `go test -tags dev ./...`

### Contract Tests

**Location:** `internal/bus/*_test.go`, no build tags.

Tests NATS event payload schemas so downstream subscribers (CrossCodex) can rely on the event structure. Each event type published by the ingest worker has a contract test verifying the payload fields, types, and serialization.

**Covers:**
- `core.ingest` — IngestRef payload
- `core.evidence.<policy_id>` — evidence event payload
- `core.policy.new` — policy event payload
- `core.target.registered` — target event payload
- Publisher identity serialization in event payloads

**Run:** `go test ./internal/bus/...`

### BDD E2E Tests (Ginkgo)

**Location:** `internal/e2e/`, build tag `integration`.

Tests complete workflows end-to-end in-process with embedded Tessera and NATS. Uses Ginkgo BDD syntax (`Describe`/`Context`/`It`) to describe expected behavior from the user's perspective.

**Covers:**
- Submit TargetRegistration → publisher trust populated in NATS KV
- Submit evidence as trusted publisher → accepted, log_index returned
- Submit evidence as untrusted publisher → rejected
- OCI bundle import → each artifact ingested through Tessera
- Target registration with publisher additions and removals

**Run:** `go test -tags integration ./internal/e2e/ -run "<TestName>"`

### Security Evaluation Tests

**Location:** `internal/e2e/`, build tag `integration`.

Tests that security properties hold, using Gemara `ControlEvaluation` assessments mapped to the Layer 2 control catalog. Each test evaluates an assessment requirement from `transparency-controls.yaml`. Produces a Gemara EvaluationLog YAML artifact and SARIF JSON uploaded to GitHub Security via `codeql-action/upload-sarif`.

These are NOT workflow tests — they verify that specific security properties are maintained regardless of how the workflow is invoked.

**Covers:**
- CTRL-AE-01: Witness cosigned checkpoints
- CTRL-CV-01: Persistent checkpoint signer
- CTRL-CV-02: Standard tlog-tiles read API
- CTRL-CV-03: Witnessed status endpoint
- All Active controls in `transparency-controls.yaml`

**Output:**
- `testdata/evaluation-log.yaml` — Gemara EvaluationLog
- `testdata/evaluation-results.sarif` — SARIF for GitHub Security tab

**Run:** `go test -tags integration ./internal/e2e/ -run "Transparency"`

### Smoke Tests

**Location:** `scripts/smoke-test.sh`.

Tests the full deployed stack against docker compose with real containers. Verifies that the infrastructure works: JWT auth, Tessera append, real witness cosignature, tiles serving.

**Covers:**
- Service health (NATS, ingest, witness, testjwks)
- JWT acquisition and authentication
- Evidence submission via `POST /api/ingest`
- Checkpoint publication with witness cosignature (2+ signatures)
- Witnessed status reporting
- Entry bundle readable from tlog-tiles API

**Run:**
```bash
./scripts/setup-witness.sh
cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d
cd ../.. && ./scripts/smoke-test.sh
```

## What Must Be Tested Before Merge

| Change type | Required tests |
|:--|:--|
| New function or store operation | Unit test |
| New NATS event type | Contract test for payload schema |
| New workflow or user-facing flow | BDD E2E test |
| New security property claim | Threat + control catalog entries, security evaluation test, SARIF output |
| New API endpoint or infrastructure change | Smoke test step |
| Fail-closed behavior change | Unit test explicitly testing unavailability |
| Ingest worker logic change | Unit test for ack/nak/term outcome |

## Threat Model Integration

Security claims are not tested by assertion alone. The process:

1. Add threat to `internal/e2e/testdata/transparency-threats.yaml`
2. Add control + assessment requirements to `transparency-controls.yaml`
3. Write security evaluation test implementing the assessment
4. Test produces Gemara EvaluationLog + SARIF uploaded to GitHub Security
5. ADR references the control ID

An unverified security claim must not be stated as an accepted guarantee.

## What We Don't Test

- **PostgreSQL** — removed entirely
- **CrossCodex queries** — downstream service, not our concern
- **UI/browser** — no frontend in this repo
- **Production witness infrastructure** — smoke test uses omniwitness built from source; production witnesses are external

## Related

- [Remove PostgreSQL](remove-postgresql.md) — why Postgres tests were deleted
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — security evaluation test details
- Control catalog: `internal/e2e/testdata/transparency-controls.yaml`
