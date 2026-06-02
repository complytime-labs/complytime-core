# Phase 1: Trust Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace binary `certified` flag with queryable trust signals table. Backward compatible - no breaking changes.

**Architecture:** Add `trust_signals` table with one row per verification check (schema, provenance, executor). Layer 2 writes to BOTH old `certifications` table AND new `trust_signals` table. `evidence.certified` becomes aggregate of trust_signals.

**Tech Stack:** Go 1.22, PostgreSQL 15, pgx v5

**Spec Reference:** `docs/superpowers/specs/2026-05-29-stratified-trust-layers-design.md` - Migration Phase 1

---

## File Structure

**New files:**
- `internal/postgres/migrations/030_add_trust_signals.sql` - trust_signals table schema
- `internal/store/trust_signals.go` - trust signals data access layer
- `internal/store/trust_signals_test.go` - trust signals tests

**Modified files:**
- `internal/certifier/certifier.go` - add TrustSignal type
- `internal/events/certification_handler.go` - write trust signals
- `internal/store/store_evidence.go` - aggregate certified from trust signals

---

### Task 1: Create trust_signals Table Schema

**Files:**
- Create: `internal/postgres/migrations/030_add_trust_signals.sql`

- [ ] **Step 1: Write migration SQL**

```sql
-- Migration 030: Add trust_signals table
-- Phase 1: Trust Signals (backward compatible)

CREATE TABLE IF NOT EXISTS trust_signals (
    evidence_id       TEXT NOT NULL,
    layer             TEXT NOT NULL,  -- 'identity', 'quality', 'attestation'
    check_name        TEXT NOT NULL,  -- 'schema', 'provenance', 'executor', 'freshness', 'relevance', 'publisher_auth'
    result            TEXT NOT NULL,  -- 'pass', 'fail', 'skip', 'error'
    reason            TEXT NOT NULL DEFAULT '',
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    PRIMARY KEY (evidence_id, layer, check_name),
    
    CONSTRAINT trust_signals_layer_chk CHECK (
        layer IN ('identity', 'quality', 'attestation')
    ),
    CONSTRAINT trust_signals_result_chk CHECK (
        result IN ('pass', 'fail', 'skip', 'error')
    )
);

CREATE INDEX IF NOT EXISTS idx_trust_signals_result 
    ON trust_signals(evidence_id, result);

CREATE INDEX IF NOT EXISTS idx_trust_signals_layer 
    ON trust_signals(layer, check_name, result);

COMMENT ON TABLE trust_signals IS 
    'Queryable trust signals for each evidence verification check';
COMMENT ON COLUMN trust_signals.layer IS 
    'Verification layer: identity (Layer 1), quality (Layer 2), attestation (Layer 3)';
COMMENT ON COLUMN trust_signals.check_name IS 
    'Specific check: publisher_auth, schema, provenance, executor, freshness, relevance';
COMMENT ON COLUMN trust_signals.result IS 
    'Check result: pass (passed), fail (failed), skip (not applicable), error (check failed to run)';
```

- [ ] **Step 2: Test migration applies cleanly**

Run:
```bash
POSTGRES_URL="postgresql://localhost:5432/complytime_test" go run cmd/migrate/main.go up
```

Expected: Migration 030 applied, no errors

- [ ] **Step 3: Verify table structure**

Run:
```bash
psql $POSTGRES_URL -c "\d trust_signals"
```

Expected: Table with columns evidence_id, layer, check_name, result, reason, checked_at

- [ ] **Step 4: Test rollback**

Run:
```bash
POSTGRES_URL="postgresql://localhost:5432/complytime_test" go run cmd/migrate/main.go down
```

Expected: trust_signals table dropped cleanly

- [ ] **Step 5: Re-apply migration**

Run:
```bash
POSTGRES_URL="postgresql://localhost:5432/complytime_test" go run cmd/migrate/main.go up
```

Expected: Migration 030 applied again

- [ ] **Step 6: Commit**

```bash
git add internal/postgres/migrations/030_add_trust_signals.sql
git commit -m "feat: add trust_signals table for queryable verification results

Replaces binary certified flag with per-check trust signals.
Backward compatible - evidence.certified stays as aggregate.

Relates to Phase 1 of stratified trust layers architecture.
"
```

---

### Task 2: Add TrustSignal Type to Certifier Package

**Files:**
- Modify: `internal/certifier/certifier.go`

- [ ] **Step 1: Write test for TrustSignal type**

Create: `internal/certifier/certifier_test.go`

```go
// SPDX-License-Identifier: Apache-2.0

package certifier_test

import (
	"testing"
	
	"github.com/complytime-labs/complytime-core/internal/certifier"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignal_Valid(t *testing.T) {
	signal := certifier.TrustSignal{
		Layer:     "quality",
		CheckName: "schema",
		Result:    certifier.ResultPass,
		Reason:    "all required fields present",
	}
	
	assert.Equal(t, "quality", signal.Layer)
	assert.Equal(t, "schema", signal.CheckName)
	assert.Equal(t, certifier.ResultPass, signal.Result)
	assert.Equal(t, "all required fields present", signal.Reason)
}

func TestResult_Constants(t *testing.T) {
	assert.Equal(t, certifier.Result("pass"), certifier.ResultPass)
	assert.Equal(t, certifier.Result("fail"), certifier.ResultFail)
	assert.Equal(t, certifier.Result("skip"), certifier.ResultSkip)
	assert.Equal(t, certifier.Result("error"), certifier.ResultError)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/certifier -v
```

Expected: FAIL - TrustSignal type does not exist

- [ ] **Step 3: Add TrustSignal type to certifier.go**

Edit `internal/certifier/certifier.go` - add after existing Verdict constants:

```go
// Result represents the outcome of a trust signal check.
type Result string

const (
	ResultPass  Result = "pass"
	ResultFail  Result = "fail"
	ResultSkip  Result = "skip"
	ResultError Result = "error"
)

// TrustSignal represents the outcome of a single verification check.
// Trust signals replace the binary certified flag with queryable,
// per-check results that can be filtered and analyzed.
type TrustSignal struct {
	Layer     string // 'identity', 'quality', 'attestation'
	CheckName string // 'schema', 'provenance', 'executor', 'freshness', 'relevance', 'publisher_auth'
	Result    Result // pass, fail, skip, error
	Reason    string // Human-readable explanation
}

// ToVerdict converts a TrustSignal Result to the legacy Verdict type.
// Used for backward compatibility with existing certifier infrastructure.
func (r Result) ToVerdict() Verdict {
	switch r {
	case ResultPass:
		return VerdictPass
	case ResultFail:
		return VerdictFail
	case ResultSkip:
		return VerdictSkip
	case ResultError:
		return VerdictError
	default:
		return VerdictError
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./internal/certifier -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/certifier/certifier.go internal/certifier/certifier_test.go
git commit -m "feat(certifier): add TrustSignal type for queryable verification results

TrustSignal captures layer, check name, result, and reason for each
verification check. Replaces binary verdict with queryable signals.

Backward compatible via ToVerdict() conversion.
"
```

---

### Task 3: Create Trust Signals Store

**Files:**
- Create: `internal/store/trust_signals.go`
- Create: `internal/store/trust_signals_test.go`

- [ ] **Step 1: Write test for InsertTrustSignals**

Create: `internal/store/trust_signals_test.go`

```go
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"
	
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_InsertTrustSignals(t *testing.T) {
	ctx := context.Background()
	st := setupTestStore(t)
	defer cleanupTestStore(t, st)
	
	signals := []store.TrustSignalRow{
		{
			EvidenceID: "eval-001",
			Layer:      "quality",
			CheckName:  "schema",
			Result:     "pass",
			Reason:     "all required fields present",
		},
		{
			EvidenceID: "eval-001",
			Layer:      "quality",
			CheckName:  "provenance",
			Result:     "pass",
			Reason:     "source_registry=docker.io",
		},
	}
	
	err := st.InsertTrustSignals(ctx, signals)
	require.NoError(t, err)
	
	// Verify signals were inserted
	var count int
	err = st.Pool().QueryRow(ctx, 
		"SELECT COUNT(*) FROM trust_signals WHERE evidence_id = $1",
		"eval-001").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestStore_QueryTrustSignals(t *testing.T) {
	ctx := context.Background()
	st := setupTestStore(t)
	defer cleanupTestStore(t, st)
	
	// Insert test data
	signals := []store.TrustSignalRow{
		{
			EvidenceID: "eval-001",
			Layer:      "quality",
			CheckName:  "schema",
			Result:     "pass",
			Reason:     "all required fields present",
		},
		{
			EvidenceID: "eval-001",
			Layer:      "quality",
			CheckName:  "freshness",
			Result:     "fail",
			Reason:     "age=45d, frequency=monthly (30d cycle)",
		},
	}
	err := st.InsertTrustSignals(ctx, signals)
	require.NoError(t, err)
	
	// Query signals
	result, err := st.QueryTrustSignals(ctx, "eval-001")
	require.NoError(t, err)
	assert.Len(t, result, 2)
	
	// Verify first signal
	assert.Equal(t, "quality", result[0].Layer)
	assert.Equal(t, "schema", result[0].CheckName)
	assert.Equal(t, "pass", result[0].Result)
}

func TestStore_AggregateCertified(t *testing.T) {
	ctx := context.Background()
	st := setupTestStore(t)
	defer cleanupTestStore(t, st)
	
	tests := []struct {
		name      string
		signals   []store.TrustSignalRow
		wantCert  bool
	}{
		{
			name: "all pass",
			signals: []store.TrustSignalRow{
				{EvidenceID: "eval-001", Layer: "quality", CheckName: "schema", Result: "pass", Reason: "valid"},
				{EvidenceID: "eval-001", Layer: "quality", CheckName: "provenance", Result: "pass", Reason: "valid"},
			},
			wantCert: true,
		},
		{
			name: "one fail",
			signals: []store.TrustSignalRow{
				{EvidenceID: "eval-002", Layer: "quality", CheckName: "schema", Result: "pass", Reason: "valid"},
				{EvidenceID: "eval-002", Layer: "quality", CheckName: "freshness", Result: "fail", Reason: "stale"},
			},
			wantCert: false,
		},
		{
			name: "skip is ok",
			signals: []store.TrustSignalRow{
				{EvidenceID: "eval-003", Layer: "quality", CheckName: "schema", Result: "pass", Reason: "valid"},
				{EvidenceID: "eval-003", Layer: "quality", CheckName: "executor", Result: "skip", Reason: "no engine"},
			},
			wantCert: true,
		},
		{
			name: "error fails",
			signals: []store.TrustSignalRow{
				{EvidenceID: "eval-004", Layer: "quality", CheckName: "schema", Result: "pass", Reason: "valid"},
				{EvidenceID: "eval-004", Layer: "quality", CheckName: "relevance", Result: "error", Reason: "DB error"},
			},
			wantCert: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := st.InsertTrustSignals(ctx, tt.signals)
			require.NoError(t, err)
			
			certified := st.AggregateCertified(ctx, tt.signals[0].EvidenceID)
			assert.Equal(t, tt.wantCert, certified)
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/store -run TestStore_InsertTrustSignals -v
```

Expected: FAIL - InsertTrustSignals does not exist

- [ ] **Step 3: Implement trust signals store**

Create: `internal/store/trust_signals.go`

```go
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	
	"github.com/jackc/pgx/v5"
)

// TrustSignalRow represents a trust signal database row.
type TrustSignalRow struct {
	EvidenceID string
	Layer      string
	CheckName  string
	Result     string
	Reason     string
}

// InsertTrustSignals inserts multiple trust signals for an evidence row.
// Uses batch insert for efficiency.
func (s *Store) InsertTrustSignals(ctx context.Context, signals []TrustSignalRow) error {
	if len(signals) == 0 {
		return nil
	}
	
	batch := &pgx.Batch{}
	for _, signal := range signals {
		batch.Queue(`
			INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (evidence_id, layer, check_name)
			DO UPDATE SET
				result = EXCLUDED.result,
				reason = EXCLUDED.reason,
				checked_at = now()
		`, signal.EvidenceID, signal.Layer, signal.CheckName, signal.Result, signal.Reason)
	}
	
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	
	for i := 0; i < len(signals); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert trust signal %d: %w", i, err)
		}
	}
	
	return nil
}

// QueryTrustSignals retrieves all trust signals for an evidence row.
func (s *Store) QueryTrustSignals(ctx context.Context, evidenceID string) ([]TrustSignalRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT evidence_id, layer, check_name, result, reason
		FROM trust_signals
		WHERE evidence_id = $1
		ORDER BY layer, check_name
	`, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("query trust signals: %w", err)
	}
	defer rows.Close()
	
	var signals []TrustSignalRow
	for rows.Next() {
		var sig TrustSignalRow
		if err := rows.Scan(&sig.EvidenceID, &sig.Layer, &sig.CheckName, &sig.Result, &sig.Reason); err != nil {
			return nil, fmt.Errorf("scan trust signal: %w", err)
		}
		signals = append(signals, sig)
	}
	
	return signals, rows.Err()
}

// AggregateCertified computes the certified flag from trust signals.
// Returns true if ALL signals are "pass" or "skip", false if any are "fail" or "error".
func (s *Store) AggregateCertified(ctx context.Context, evidenceID string) bool {
	var hasFail bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM trust_signals
			WHERE evidence_id = $1
			AND result IN ('fail', 'error')
		)
	`, evidenceID).Scan(&hasFail)
	
	if err != nil {
		return false
	}
	
	return !hasFail
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/store -run "TestStore_InsertTrustSignals|TestStore_QueryTrustSignals|TestStore_AggregateCertified" -v
```

Expected: PASS all tests

- [ ] **Step 5: Commit**

```bash
git add internal/store/trust_signals.go internal/store/trust_signals_test.go
git commit -m "feat(store): add trust signals data access layer

InsertTrustSignals - batch insert with upsert on conflict
QueryTrustSignals - fetch all signals for evidence
AggregateCertified - compute certified flag from signals

Phase 1: queryable trust signals infrastructure.
"
```

---

### Task 4: Update Certification Handler to Write Trust Signals

**Files:**
- Modify: `internal/events/certification_handler.go`

- [ ] **Step 1: Write test for trust signals integration**

Add to `internal/events/certification_handler_test.go`:

```go
func TestCertificationHandler_WritesTrustSignals(t *testing.T) {
	ctx := context.Background()
	st := setupTestStore(t)
	defer cleanupTestStore(t, st)
	
	pipeline := certifier.NewPipeline(
		&certifier.SchemaCertifier{},
		&certifier.ProvenanceCertifier{KnownRegistries: map[string]bool{"docker.io": true}},
	)
	
	handler := events.CertificationHandler(ctx, pipeline, st, st)
	
	evt := events.EvidenceEvent{
		PolicyID:    "test-policy",
		RecordCount: 1,
		Timestamp:   time.Now(),
	}
	
	// Insert test evidence
	err := st.InsertEvidence(ctx, []store.EvidenceRecord{
		{
			EvidenceID:     "eval-001",
			TargetID:       "target-001",
			RuleID:         "rule-001",
			EvalResult:     "Passed",
			PolicyID:       "test-policy",
			SourceRegistry: "docker.io",
			CollectedAt:    time.Now(),
		},
	})
	require.NoError(t, err)
	
	// Run handler
	handler(evt)
	
	// Verify trust signals were written
	signals, err := st.QueryTrustSignals(ctx, "eval-001")
	require.NoError(t, err)
	assert.Greater(t, len(signals), 0, "should have trust signals")
	
	// Verify signal content
	var schemaSignal *store.TrustSignalRow
	for _, sig := range signals {
		if sig.CheckName == "schema" {
			schemaSignal = &sig
			break
		}
	}
	
	require.NotNil(t, schemaSignal, "should have schema trust signal")
	assert.Equal(t, "quality", schemaSignal.Layer)
	assert.Equal(t, "pass", schemaSignal.Result)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/events -run TestCertificationHandler_WritesTrustSignals -v
```

Expected: FAIL - trust signals not written

- [ ] **Step 3: Update certification handler to write trust signals**

Edit `internal/events/certification_handler.go` - modify the handler function:

```go
func CertificationHandler(
	ctx context.Context,
	pipeline *certifier.Pipeline,
	querier CertificationQuerier,
	writer CertificationWriter,
) func(EvidenceEvent) {
	return func(evt EvidenceEvent) {
		since := evt.Timestamp.Add(-5 * time.Minute)
		rows, err := querier.QueryRecentEvidence(ctx, evt.PolicyID, since)
		if err != nil {
			slog.Warn("certification query failed",
				"policy_id", evt.PolicyID, "error", err)
			return
		}
		if len(rows) == 0 {
			slog.Debug("no evidence rows for certification",
				"policy_id", evt.PolicyID)
			return
		}

		for _, row := range rows {
			results := pipeline.Run(ctx, row)

			// Write to certifications table (legacy)
			var certRows []CertificationRow
			for _, r := range results {
				certRows = append(certRows, CertificationRow{
					EvidenceID:       row.EvidenceID,
					Certifier:        r.Certifier,
					CertifierVersion: r.Version,
					Result:           string(r.Verdict),
					Reason:           r.Reason,
				})
			}

			if err := writer.InsertCertifications(ctx, certRows); err != nil {
				slog.Warn("certification insert failed",
					"evidence_id", row.EvidenceID, "error", err)
				continue
			}

			// Write to trust_signals table (new)
			var trustSignals []store.TrustSignalRow
			for _, r := range results {
				trustSignals = append(trustSignals, store.TrustSignalRow{
					EvidenceID: row.EvidenceID,
					Layer:      "quality",  // All certifiers are quality checks in Phase 1
					CheckName:  r.Certifier, // e.g., "schema", "provenance", "executor"
					Result:     string(r.Verdict),
					Reason:     r.Reason,
				})
			}

			// Type assertion to access InsertTrustSignals
			if trustWriter, ok := writer.(interface {
				InsertTrustSignals(context.Context, []store.TrustSignalRow) error
			}); ok {
				if err := trustWriter.InsertTrustSignals(ctx, trustSignals); err != nil {
					slog.Warn("trust signals insert failed",
						"evidence_id", row.EvidenceID, "error", err)
				}
			}

			// Compute certified from trust signals
			certified := certifier.IsCertified(results)
			if err := writer.UpdateEvidenceCertified(
				ctx, row.EvidenceID, certified,
			); err != nil {
				slog.Warn("evidence certified update failed",
					"evidence_id", row.EvidenceID, "error", err)
			} else {
				slog.Info("evidence certified",
					"evidence_id", row.EvidenceID,
					"certified", fmt.Sprintf("%t", certified),
					"policy_id", evt.PolicyID,
				)
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./internal/events -run TestCertificationHandler_WritesTrustSignals -v
```

Expected: PASS

- [ ] **Step 5: Run all certification handler tests**

Run:
```bash
go test ./internal/events -v
```

Expected: PASS all tests

- [ ] **Step 6: Commit**

```bash
git add internal/events/certification_handler.go internal/events/certification_handler_test.go
git commit -m "feat(events): write trust signals in certification handler

Phase 1: dual-write to both certifications (legacy) and trust_signals.
Backward compatible - certified flag still computed from certifier results.

Trust signals enable queryable verification results per check.
"
```

---

### Task 5: Add E2E Test for Trust Signals

**Files:**
- Modify: `internal/e2e/certification_test.go` (or create if doesn't exist)

- [ ] **Step 1: Write E2E test for trust signals**

Create or append to `internal/e2e/certification_test.go`:

```go
func TestE2E_TrustSignals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}
	
	ctx := context.Background()
	suite := setupE2ESuite(t)
	defer suite.Cleanup()
	
	// Submit evidence via ingest
	evidenceYAML := `
metadata:
  type: EvaluationLog
  id: eval-trust-signals-test
  date: "2026-05-29T12:00:00Z"

target:
  id: test-target-001

engine:
  name: trivy
  version: 0.50.0

policy:
  id: test-policy-001
  version: "1.0"

results:
  - evidence-id: evidence-001
    rule-id: CVE-2024-1234
    rule-name: Test vulnerability
    eval-result: Failed
    compliance-status: Non-Compliant
    control-id: TEST-1
    requirement-id: req-001
    collected-at: "2026-05-29T11:55:00Z"
`
	
	resp := suite.IngestEvidence(evidenceYAML)
	require.Equal(t, 200, resp.StatusCode)
	
	// Wait for certification
	time.Sleep(2 * time.Second)
	
	// Query trust signals
	var signals []struct {
		Layer     string
		CheckName string
		Result    string
		Reason    string
	}
	
	err := suite.DB.Select(ctx, &signals, `
		SELECT layer, check_name, result, reason
		FROM trust_signals
		WHERE evidence_id = 'evidence-001'
		ORDER BY check_name
	`)
	require.NoError(t, err)
	assert.Greater(t, len(signals), 0, "should have trust signals")
	
	// Verify schema check exists
	var hasSchema bool
	for _, sig := range signals {
		if sig.CheckName == "schema" {
			hasSchema = true
			assert.Equal(t, "quality", sig.Layer)
			assert.Equal(t, "pass", sig.Result)
			break
		}
	}
	assert.True(t, hasSchema, "should have schema trust signal")
	
	// Verify evidence.certified matches aggregate
	var certified bool
	err = suite.DB.QueryRow(ctx, `
		SELECT certified FROM evidence 
		WHERE evidence_id = 'evidence-001' 
		AND control_id = 'TEST-1' 
		AND requirement_id = 'req-001'
	`).Scan(&certified)
	require.NoError(t, err)
	
	// Should be certified if all signals pass
	allPass := true
	for _, sig := range signals {
		if sig.Result == "fail" || sig.Result == "error" {
			allPass = false
			break
		}
	}
	assert.Equal(t, allPass, certified, "certified should match aggregate of trust signals")
}
```

- [ ] **Step 2: Run E2E test**

Run:
```bash
go test ./internal/e2e -run TestE2E_TrustSignals -v
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/e2e/certification_test.go
git commit -m "test(e2e): add trust signals E2E test

Verifies:
- Trust signals written during certification
- Signals contain correct layer, check name, result
- evidence.certified matches aggregate of trust signals

Phase 1: backward compatible trust signals.
"
```

---

### Task 6: Update Documentation

**Files:**
- Modify: `README.md` or `docs/architecture.md`

- [ ] **Step 1: Document trust signals schema**

Add to docs (e.g., `docs/architecture.md`):

```markdown
## Trust Signals

Phase 1 of the stratified trust layers architecture introduces **queryable trust signals**.

### Schema

Each verification check writes one row to `trust_signals`:

| Column | Type | Description |
|--------|------|-------------|
| evidence_id | TEXT | Evidence row identifier |
| layer | TEXT | Verification layer: `quality` (Phase 1), `identity`/`attestation` (future) |
| check_name | TEXT | Check identifier: `schema`, `provenance`, `executor`, `freshness`, `relevance` |
| result | TEXT | `pass`, `fail`, `skip`, `error` |
| reason | TEXT | Human-readable explanation |
| checked_at | TIMESTAMPTZ | When check ran |

### Querying Trust Signals

**Find evidence where freshness failed:**
```sql
SELECT evidence_id, target_id, collected_at
FROM evidence e
JOIN trust_signals ts ON ts.evidence_id = e.evidence_id
WHERE ts.check_name = 'freshness'
AND ts.result = 'fail';
```

**Trust signal distribution:**
```sql
SELECT check_name, result, COUNT(*)
FROM trust_signals
WHERE checked_at > NOW() - INTERVAL '7 days'
GROUP BY check_name, result
ORDER BY check_name, result;
```

### Backward Compatibility

Phase 1 is fully backward compatible:
- `evidence.certified` still exists (computed from trust signals aggregate)
- `certifications` table still populated (legacy)
- Existing queries work unchanged
```

- [ ] **Step 2: Commit**

```bash
git add docs/architecture.md
git commit -m "docs: document trust signals schema and queries

Phase 1: queryable trust signals replace binary certified flag.
Backward compatible - existing tables and queries unchanged.
"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ Task 1: trust_signals table schema (spec: Database Schema section)
- ✅ Task 2: TrustSignal type (spec: Layer 2 Quality Validators section)
- ✅ Task 3: Store methods (spec: Database Schema section)
- ✅ Task 4: Certification handler writes signals (spec: Migration Phase 1)
- ✅ Task 5: E2E test (spec: Migration Phase 1 testing)
- ✅ Task 6: Documentation (spec: Migration Phase 1)

**Placeholders:** None - all code blocks complete, exact file paths, actual commands.

**Type consistency:**
- TrustSignal type matches TrustSignalRow in store ✅
- Result constants match database constraints ✅
- Layer/CheckName values consistent across tasks ✅

**Migration verification:** Task 1 includes rollback test ✅

**Backward compatibility:** Phase 1 maintains evidence.certified and certifications table ✅

---

## Next Phase

After Phase 1 completes, proceed to:
**Phase 2: Target Authorization** - Add target_trusted_publishers table and PublisherAuthorizationValidator (warnings only, no enforcement).

See `docs/superpowers/specs/2026-05-29-stratified-trust-layers-design.md` Migration Phase 2.
