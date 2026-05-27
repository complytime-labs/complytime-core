# Policy Enrollment and Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable publishers to register targets with dimensional metadata and discover applicable Gemara Policy artifacts via a query API, with NATS notifications when new policies arrive.

**Architecture:** Add a TargetRegistration artifact type to the ingest pipeline, a `targets` table for dimension-based queries, a policy query API endpoint, and NATS events for policy and target changes. The existing OCI import handler is updated to route artifacts through Tessera so all artifacts receive a `tessera_log_index`. Witness logs advisory warnings for unregistered targets.

**Tech Stack:** Go, PostgreSQL (pgx), NATS, Echo HTTP framework, Tessera transparency log, Gemara YAML

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/postgres/migrations/022_targets_table.sql` | Create | Targets table + indexes |
| `internal/postgres/migrations/023_bundle_artifacts.sql` | Create | Bundle artifacts table |
| `internal/postgres/migrations/024_policy_dimensions.sql` | Create | Add dimension + timeline columns to policies |
| `internal/store/store.go` | Modify | TargetStore interface, TargetRow type, Insert/Query methods |
| `internal/store/handlers_targets.go` | Create | Policy query API handler + route registration |
| `internal/store/handlers_targets_test.go` | Create | Tests for policy query handler |
| `internal/events/nats.go` | Modify | PolicyEvent, TargetRegisteredEvent, publish/subscribe methods |
| `internal/events/nats_test.go` | Modify | Tests for new event types |
| `internal/store/ingest_worker.go` | Modify | Add TargetRegistration case to switch |
| `internal/store/ingest_handler.go` | Modify | Add TargetRegistration YAML parser |
| `internal/store/handlers_import.go` | Modify | Route OCI import through Tessera |
| `internal/store/handlers.go` | Modify | Add Targets field to Stores, register target routes |
| `cmd/gateway/main.go` | Modify | Wire TargetStore into Stores struct |

---

## Task 1: Database Migration — Targets Table

**Files:**
- Create: `internal/postgres/migrations/022_targets_table.sql`

- [ ] **Step 1: Write migration**

```sql
-- internal/postgres/migrations/022_targets_table.sql
-- SPDX-License-Identifier: Apache-2.0
-- Migration 022: Create targets table for publisher-registered target dimensions

CREATE TABLE IF NOT EXISTS targets (
    target_id           TEXT NOT NULL,
    tessera_log_index   BIGINT NOT NULL,
    target_name         TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    technologies        TEXT[] NOT NULL DEFAULT '{}',
    geopolitical        TEXT[] NOT NULL DEFAULT '{}',
    sensitivity         TEXT[] NOT NULL DEFAULT '{}',
    users               TEXT[] NOT NULL DEFAULT '{}',
    groups              TEXT[] NOT NULL DEFAULT '{}',
    registered_at       TIMESTAMPTZ NOT NULL,
    registered_by       TEXT NOT NULL,

    PRIMARY KEY (target_id, tessera_log_index)
);

CREATE INDEX IF NOT EXISTS idx_targets_registered_at ON targets(target_id, registered_at DESC);

COMMENT ON TABLE targets IS 'Append-only target registrations with dimensional metadata for policy matching';
COMMENT ON COLUMN targets.registered_by IS 'JWT sub claim of the publisher who registered this target';
```

- [ ] **Step 2: Commit**

```bash
git add internal/postgres/migrations/022_targets_table.sql
git commit -m "feat: add targets table migration for policy enrollment

Append-only table stores target registrations with dimensional metadata
(technologies, geopolitical, sensitivity, users, groups) for policy matching.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Database Migration — Bundle Artifacts Table

**Files:**
- Create: `internal/postgres/migrations/023_bundle_artifacts.sql`

- [ ] **Step 1: Write migration**

```sql
-- internal/postgres/migrations/023_bundle_artifacts.sql
-- SPDX-License-Identifier: Apache-2.0
-- Migration 023: Create bundle_artifacts table for OCI bundle tracking

CREATE TABLE IF NOT EXISTS bundle_artifacts (
    bundle_id           TEXT NOT NULL,
    tessera_log_index   BIGINT NOT NULL,
    artifact_type       TEXT NOT NULL,
    artifact_id         TEXT NOT NULL,
    oci_reference       TEXT,
    imported_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (bundle_id, tessera_log_index)
);

CREATE INDEX IF NOT EXISTS idx_bundle_artifacts_type ON bundle_artifacts(bundle_id, artifact_type);

COMMENT ON TABLE bundle_artifacts IS 'Tracks all artifacts belonging to an OCI bundle import for effective policy resolution';
```

- [ ] **Step 2: Commit**

```bash
git add internal/postgres/migrations/023_bundle_artifacts.sql
git commit -m "feat: add bundle_artifacts table migration for OCI bundle tracking

Links multiple artifacts (Policy, ControlCatalog, Mappings) by bundle_id
so the system can reconstruct the full bundle and derive effective policy.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Database Migration — Policy Dimension Columns

**Files:**
- Create: `internal/postgres/migrations/024_policy_dimensions.sql`

- [ ] **Step 1: Write migration**

```sql
-- internal/postgres/migrations/024_policy_dimensions.sql
-- SPDX-License-Identifier: Apache-2.0
-- Migration 024: Add dimension and timeline columns to policies table

ALTER TABLE policies ADD COLUMN IF NOT EXISTS technologies TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS geopolitical TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS sensitivity TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS users TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS groups TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_start TIMESTAMPTZ;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_end TIMESTAMPTZ;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS bundle_id TEXT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tessera_log_index BIGINT;

CREATE INDEX IF NOT EXISTS idx_policies_bundle ON policies(bundle_id) WHERE bundle_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policies_timeline ON policies(evaluation_timeline_start, evaluation_timeline_end);

COMMENT ON COLUMN policies.bundle_id IS 'Links policy to OCI bundle for effective policy resolution';
COMMENT ON COLUMN policies.tessera_log_index IS 'Tessera transparency log position';
```

- [ ] **Step 2: Commit**

```bash
git add internal/postgres/migrations/024_policy_dimensions.sql
git commit -m "feat: add dimension and timeline columns to policies table

Adds technologies, geopolitical, sensitivity, users, groups arrays
plus evaluation_timeline_start/end and bundle_id for policy enrollment.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: TargetStore Interface and Implementation

**Files:**
- Modify: `internal/store/store.go`

- [ ] **Step 1: Write failing test**

```go
// internal/store/store_target_test.go
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetRow_InsertAndQuery(t *testing.T) {
	// This test validates types and method signatures compile correctly.
	// Full integration tests require POSTGRES_TEST_URL.
	var ts TargetStore = (*Store)(nil) // Compile-time check
	_ = ts

	row := TargetRow{
		TargetID:        "prod-cluster",
		TesseraLogIndex: 42,
		TargetName:      "Production K8s Cluster",
		TargetType:      "kubernetes-cluster",
		Technologies:    []string{"kubernetes", "postgresql"},
		Geopolitical:    []string{"EU"},
		Sensitivity:     []string{"confidential"},
		Users:           []string{},
		Groups:          []string{"platform"},
		RegisteredAt:    time.Now().UTC(),
		RegisteredBy:    "repo:org/infra:ref:refs/heads/main",
	}

	assert.Equal(t, "prod-cluster", row.TargetID)
	assert.Equal(t, uint64(42), row.TesseraLogIndex)
	assert.Contains(t, row.Technologies, "kubernetes")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store -v -run TestTargetRow`
Expected: FAIL with "undefined: TargetStore" or "undefined: TargetRow"

- [ ] **Step 3: Add TargetStore interface and TargetRow type**

Add to `internal/store/store.go` after the existing interface definitions (around line 124):

```go
// TargetStore defines operations for target registrations.
type TargetStore interface {
	InsertTarget(ctx context.Context, t TargetRow) error
	GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*TargetRow, error)
	ListTargets(ctx context.Context) ([]TargetRow, error)
}
```

Add compile-time check in the `var` block (around line 148):

```go
_ TargetStore = (*Store)(nil)
```

Add the TargetRow type after the Policy struct:

```go
// TargetRow represents a target registration with dimensional metadata.
type TargetRow struct {
	TargetID        string    `json:"target_id"`
	TesseraLogIndex uint64    `json:"tessera_log_index"`
	TargetName      string    `json:"target_name"`
	TargetType      string    `json:"target_type"`
	Technologies    []string  `json:"technologies"`
	Geopolitical    []string  `json:"geopolitical"`
	Sensitivity     []string  `json:"sensitivity"`
	Users           []string  `json:"users"`
	Groups          []string  `json:"groups"`
	RegisteredAt    time.Time `json:"registered_at"`
	RegisteredBy    string    `json:"registered_by"`
}
```

- [ ] **Step 4: Implement InsertTarget**

Add to `internal/store/store.go`:

```go
func (s *Store) InsertTarget(ctx context.Context, t TargetRow) error {
	const q = `INSERT INTO targets (
		target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	ON CONFLICT (target_id, tessera_log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q,
		t.TargetID, t.TesseraLogIndex, t.TargetName, t.TargetType,
		t.Technologies, t.Geopolitical, t.Sensitivity, t.Users, t.Groups,
		t.RegisteredAt, t.RegisteredBy,
	)
	if err != nil {
		return fmt.Errorf("insert target: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Implement GetLatestTarget**

```go
func (s *Store) GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*TargetRow, error) {
	const q = `SELECT target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	FROM targets
	WHERE target_id = $1 AND registered_at <= $2
	ORDER BY registered_at DESC
	LIMIT 1`

	var t TargetRow
	err := s.pool.QueryRow(ctx, q, targetID, asOf).Scan(
		&t.TargetID, &t.TesseraLogIndex, &t.TargetName, &t.TargetType,
		&t.Technologies, &t.Geopolitical, &t.Sensitivity, &t.Users, &t.Groups,
		&t.RegisteredAt, &t.RegisteredBy,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest target: %w", err)
	}
	return &t, nil
}
```

- [ ] **Step 6: Implement ListTargets**

```go
func (s *Store) ListTargets(ctx context.Context) ([]TargetRow, error) {
	const q = `SELECT DISTINCT ON (target_id)
		target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	FROM targets
	ORDER BY target_id, registered_at DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()

	var out []TargetRow
	for rows.Next() {
		var t TargetRow
		if err := rows.Scan(
			&t.TargetID, &t.TesseraLogIndex, &t.TargetName, &t.TargetType,
			&t.Technologies, &t.Geopolitical, &t.Sensitivity, &t.Users, &t.Groups,
			&t.RegisteredAt, &t.RegisteredBy,
		); err != nil {
			return nil, fmt.Errorf("scan target row: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/store -v -run TestTargetRow`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/store/store.go internal/store/store_target_test.go
git commit -m "feat: add TargetStore interface and implementation

- TargetRow type with dimensional metadata
- InsertTarget: append-only insert to targets table
- GetLatestTarget: temporal query for most recent registration
- ListTargets: distinct latest registration per target_id

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: NATS Events for Policy and Target Registration

**Files:**
- Modify: `internal/events/nats.go`

- [ ] **Step 1: Write failing test**

```go
// internal/events/nats_events_test.go
package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyEvent_JSON(t *testing.T) {
	evt := PolicyEvent{
		LogIndex: 42,
		PolicyID: "infra-security-baseline",
	}

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var decoded PolicyEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), decoded.LogIndex)
	assert.Equal(t, "infra-security-baseline", decoded.PolicyID)
	assert.False(t, decoded.Timestamp.IsZero())
}

func TestTargetRegisteredEvent_JSON(t *testing.T) {
	evt := TargetRegisteredEvent{
		LogIndex:     15,
		TargetID:     "prod-cluster",
		RegisteredBy: "repo:org/infra:ref:refs/heads/main",
	}

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var decoded TargetRegisteredEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, uint64(15), decoded.LogIndex)
	assert.Equal(t, "prod-cluster", decoded.TargetID)
	assert.Equal(t, "repo:org/infra:ref:refs/heads/main", decoded.RegisteredBy)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/events -v -run TestPolicyEvent`
Expected: FAIL with "undefined: PolicyEvent"

- [ ] **Step 3: Add event types and subjects to nats.go**

Add after the existing `SubjectIngestRaw` constant in `internal/events/nats.go`:

```go
const (
	SubjectPolicyNew          = "core.policy.new"
	SubjectTargetRegistered   = "core.target.registered"
)
```

Add event struct definitions after the existing `IngestRawEvent` struct:

```go
// PolicyEvent is published when a new Policy artifact is ingested.
type PolicyEvent struct {
	LogIndex  uint64    `json:"log_index"`
	PolicyID  string    `json:"policy_id"`
	Timestamp time.Time `json:"timestamp"`
}

// TargetRegisteredEvent is published when a TargetRegistration is ingested.
type TargetRegisteredEvent struct {
	LogIndex     uint64    `json:"log_index"`
	TargetID     string    `json:"target_id"`
	RegisteredBy string    `json:"registered_by"`
	Timestamp    time.Time `json:"timestamp"`
}
```

- [ ] **Step 4: Add publish methods**

```go
// PublishPolicyNew broadcasts that a new Policy artifact was ingested.
func (b *Bus) PublishPolicyNew(logIndex uint64, policyID string) {
	if b == nil || b.conn == nil {
		return
	}
	evt := PolicyEvent{
		LogIndex:  logIndex,
		PolicyID:  policyID,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	if err := b.conn.Publish(SubjectPolicyNew, data); err != nil {
		slog.Warn("nats publish failed", "subject", SubjectPolicyNew, "error", err)
	}
}

// PublishTargetRegistered broadcasts that a new target was registered.
func (b *Bus) PublishTargetRegistered(logIndex uint64, targetID, registeredBy string) {
	if b == nil || b.conn == nil {
		return
	}
	evt := TargetRegisteredEvent{
		LogIndex:     logIndex,
		TargetID:     targetID,
		RegisteredBy: registeredBy,
		Timestamp:    time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	if err := b.conn.Publish(SubjectTargetRegistered, data); err != nil {
		slog.Warn("nats publish failed", "subject", SubjectTargetRegistered, "error", err)
	}
}
```

- [ ] **Step 5: Fix test — add Timestamp initialization**

Update the test to set Timestamp before marshaling:

```go
func TestPolicyEvent_JSON(t *testing.T) {
	evt := PolicyEvent{
		LogIndex:  42,
		PolicyID:  "infra-security-baseline",
		Timestamp: time.Now().UTC(),
	}
	// ...
}

func TestTargetRegisteredEvent_JSON(t *testing.T) {
	evt := TargetRegisteredEvent{
		LogIndex:     15,
		TargetID:     "prod-cluster",
		RegisteredBy: "repo:org/infra:ref:refs/heads/main",
		Timestamp:    time.Now().UTC(),
	}
	// ...
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/events -v -run "TestPolicyEvent|TestTargetRegistered"`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/events/nats.go internal/events/nats_events_test.go
git commit -m "feat: add NATS events for policy and target registration

- PolicyEvent published on core.policy.new when Policy ingested
- TargetRegisteredEvent published on core.target.registered
- Both follow existing nil-safe publish pattern
- JSON serialization tests

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: IngestWorker — Handle TargetRegistration

**Files:**
- Modify: `internal/store/ingest_worker.go`
- Modify: `internal/store/ingest_handler.go`
- Modify: `internal/store/handlers.go`

- [ ] **Step 1: Add TargetStore to Stores struct**

In `internal/store/handlers.go`, add the Targets field to the Stores struct:

```go
type Stores struct {
	// ... existing fields ...
	Targets         TargetStore
	// ... rest of fields ...
}
```

- [ ] **Step 2: Add TargetRegistration parser to ingest_handler.go**

Add to `internal/store/ingest_handler.go`:

```go
// TargetRegistrationYAML represents the parsed TargetRegistration artifact.
type TargetRegistrationYAML struct {
	Metadata struct {
		Type string `yaml:"type"`
		ID   string `yaml:"id"`
		Date string `yaml:"date"`
	} `yaml:"metadata"`
	Target struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
		Type string `yaml:"type"`
	} `yaml:"target"`
	Dimensions struct {
		Technologies []string `yaml:"technologies"`
		Geopolitical []string `yaml:"geopolitical"`
		Sensitivity  []string `yaml:"sensitivity"`
		Users        []string `yaml:"users"`
		Groups       []string `yaml:"groups"`
	} `yaml:"dimensions"`
}

func parseTargetRegistration(data []byte) (*TargetRegistrationYAML, error) {
	var reg TargetRegistrationYAML
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse TargetRegistration YAML: %w", err)
	}
	if reg.Target.ID == "" {
		return nil, fmt.Errorf("missing target.id")
	}
	return &reg, nil
}
```

- [ ] **Step 3: Add TargetRegistration case to IngestWorker**

In `internal/store/ingest_worker.go`, add after the existing `MappingDocumentArtifact` case (before `default`):

```go
	case "TargetRegistration":
		handleTargetRegistration(ctx, evt, stores.Targets, pub, tracker)
```

Note: Since `TargetRegistration` is a CUE extension and may not yet exist in the go-gemara library as an `ArtifactType` constant, detect it via string matching. Update the switch to use `artifactType.String()` for this case.

Modify the top of `IngestWorker` to handle the string-based detection:

```go
return func(evt events.IngestRawEvent) {
	slog.Info("async ingest started", "job_id", evt.JobID)

	artifactType, err := detectArtifactType(evt.YAML)
	if err != nil {
		// Fall back to string-based detection for CUE extensions
		typeStr := detectArtifactTypeString(evt.YAML)
		if typeStr == "TargetRegistration" {
			handleTargetRegistration(ctx, evt, stores.Targets, pub, tracker)
			return
		}
		tracker.Fail(evt.JobID, fmt.Sprintf("invalid artifact: %v", err))
		slog.Warn("async ingest: invalid artifact", "job_id", evt.JobID, "error", err)
		return
	}
	// ... existing switch statement ...
}
```

Add `detectArtifactTypeString` to `ingest_handler.go`:

```go
func detectArtifactTypeString(data []byte) string {
	var hdr struct {
		Metadata struct {
			Type string `yaml:"type"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &hdr); err != nil {
		return ""
	}
	return hdr.Metadata.Type
}
```

- [ ] **Step 4: Implement handleTargetRegistration**

Add to `internal/store/ingest_worker.go`:

```go
func handleTargetRegistration(
	ctx context.Context,
	evt events.IngestRawEvent,
	targets TargetStore,
	pub EventPublisher,
	tracker *IngestTracker,
) {
	reg, err := parseTargetRegistration(evt.YAML)
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("parse failed: %v", err))
		slog.Warn("async ingest: TargetRegistration parse failed", "job_id", evt.JobID, "error", err)
		return
	}

	registeredAt, err := time.Parse(time.RFC3339, reg.Metadata.Date)
	if err != nil {
		registeredAt = time.Now().UTC()
	}

	row := TargetRow{
		TargetID:        reg.Target.ID,
		TesseraLogIndex: evt.LogIndex,
		TargetName:      reg.Target.Name,
		TargetType:      reg.Target.Type,
		Technologies:    reg.Dimensions.Technologies,
		Geopolitical:    reg.Dimensions.Geopolitical,
		Sensitivity:     reg.Dimensions.Sensitivity,
		Users:           reg.Dimensions.Users,
		Groups:          reg.Dimensions.Groups,
		RegisteredAt:    registeredAt,
		RegisteredBy:    evt.PublisherIdentity.Sub,
	}

	if err := targets.InsertTarget(ctx, row); err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("insert failed: %v", err))
		slog.Error("async ingest: TargetRegistration insert failed", "job_id", evt.JobID, "error", err)
		return
	}

	if pub != nil {
		pub.PublishTargetRegistered(evt.LogIndex, reg.Target.ID, evt.PublisherIdentity.Sub)
	}

	tracker.CompleteArtifact(evt.JobID, reg.Target.ID, "TargetRegistration")
	slog.Info("async ingest completed",
		"job_id", evt.JobID,
		"type", "TargetRegistration",
		"target_id", reg.Target.ID,
	)
}
```

- [ ] **Step 5: Update EventPublisher interface**

Add the new publish methods to the `EventPublisher` interface in `internal/store/handlers.go`:

```go
type EventPublisher interface {
	PublishEvidence(policyID string, recordCount int)
	PublishDraftAuditLog(draftID, policyID, summary string)
	PublishPolicyNew(logIndex uint64, policyID string)
	PublishTargetRegistered(logIndex uint64, targetID, registeredBy string)
}
```

- [ ] **Step 6: Update Policy ingestion to publish NATS event**

In `internal/store/ingest_worker.go`, update the `PolicyArtifact` case:

```go
case gemara.PolicyArtifact:
	handleArtifactStore(evt, tracker, func() (string, string, error) {
		art, err := storePolicyFromContent(ctx, stores.Policies, stores.Controls,
			string(evt.YAML))
		if err == nil && pub != nil {
			pub.PublishPolicyNew(evt.LogIndex, art.ID)
		}
		return art.ID, art.Type, err
	})
```

- [ ] **Step 7: Build to verify compilation**

Run: `go build ./...`
Expected: Build succeeds

- [ ] **Step 8: Commit**

```bash
git add internal/store/ingest_worker.go internal/store/ingest_handler.go internal/store/handlers.go
git commit -m "feat: add TargetRegistration support to ingest pipeline

- Parse TargetRegistration YAML via CUE extension type detection
- Insert target with dimensions into targets table
- Publish core.target.registered NATS event
- Publish core.policy.new when Policy artifacts ingested
- Update EventPublisher interface with new methods

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Policy Query API — Dimension Matching

**Files:**
- Create: `internal/store/handlers_targets.go`
- Create: `internal/store/handlers_targets_test.go`

- [ ] **Step 1: Write failing test**

```go
// internal/store/handlers_targets_test.go
package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTargetStore struct {
	targets []TargetRow
}

func (f *fakeTargetStore) InsertTarget(_ context.Context, t TargetRow) error {
	f.targets = append(f.targets, t)
	return nil
}

func (f *fakeTargetStore) GetLatestTarget(_ context.Context, targetID string, asOf time.Time) (*TargetRow, error) {
	for i := len(f.targets) - 1; i >= 0; i-- {
		t := f.targets[i]
		if t.TargetID == targetID && !t.RegisteredAt.After(asOf) {
			return &t, nil
		}
	}
	return nil, nil
}

func (f *fakeTargetStore) ListTargets(_ context.Context) ([]TargetRow, error) {
	return f.targets, nil
}

type fakePolicyStoreWithDimensions struct {
	policies []PolicyWithDimensions
}

func (f *fakePolicyStoreWithDimensions) QueryPoliciesByDimensions(_ context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error) {
	var result []PolicyWithDimensions
	for _, p := range f.policies {
		if arraysOverlap(p.Technologies, dims.Technologies) ||
			arraysOverlap(p.Geopolitical, dims.Geopolitical) ||
			arraysOverlap(p.Sensitivity, dims.Sensitivity) {
			if dims.Timestamp.IsZero() ||
				(!p.EvaluationStart.IsZero() && !dims.Timestamp.Before(p.EvaluationStart) &&
					!p.EvaluationEnd.IsZero() && !dims.Timestamp.After(p.EvaluationEnd)) {
				result = append(result, p)
			}
		}
	}
	return result, nil
}

func TestPolicyQueryHandler_MatchesDimensions(t *testing.T) {
	ts := &fakeTargetStore{
		targets: []TargetRow{
			{
				TargetID:     "prod-cluster",
				TargetName:   "Production K8s",
				TargetType:   "kubernetes-cluster",
				Technologies: []string{"kubernetes", "postgresql"},
				Geopolitical: []string{"EU"},
				Sensitivity:  []string{"confidential"},
				RegisteredAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	now := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
	ps := &fakePolicyStoreWithDimensions{
		policies: []PolicyWithDimensions{
			{
				LogIndex:        42,
				PolicyID:        "infra-baseline",
				Title:           "Infrastructure Baseline",
				Technologies:    []string{"kubernetes"},
				EvaluationStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				EvaluationEnd:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/policies?target_id=prod-cluster&timestamp="+now.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := policyQueryHandler(ts, ps)
	err := handler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp PolicyQueryResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "prod-cluster", resp.Target.ID)
	require.Len(t, resp.ApplicablePolicies, 1)
	assert.Equal(t, "infra-baseline", resp.ApplicablePolicies[0].PolicyID)
}

func TestPolicyQueryHandler_TargetNotFound(t *testing.T) {
	ts := &fakeTargetStore{targets: []TargetRow{}}
	ps := &fakePolicyStoreWithDimensions{}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/policies?target_id=unknown&timestamp=2026-05-26T10:00:00Z", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := policyQueryHandler(ts, ps)
	err := handler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store -v -run TestPolicyQueryHandler`
Expected: FAIL with undefined types

- [ ] **Step 3: Implement policy query handler**

Create `internal/store/handlers_targets.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func registerTargetRoutes(g *echo.Group, s Stores) {
	if s.Targets == nil {
		return
	}
	g.GET("/policies/discover", policyQueryHandler(s.Targets, s.PolicyDimensions))
	g.GET("/targets", listTargetsHandler(s.Targets))
}

// PolicyDimensionStore defines queries for policies with dimension matching.
type PolicyDimensionStore interface {
	QueryPoliciesByDimensions(ctx context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error)
}

// DimensionQuery holds parameters for dimension-based policy matching.
type DimensionQuery struct {
	Technologies []string
	Geopolitical []string
	Sensitivity  []string
	Users        []string
	Groups       []string
	Timestamp    time.Time
}

// PolicyWithDimensions represents a policy with its dimensional metadata.
type PolicyWithDimensions struct {
	LogIndex        uint64    `json:"log_index"`
	PolicyID        string    `json:"policy_id"`
	Title           string    `json:"title"`
	Version         string    `json:"version,omitempty"`
	Technologies    []string  `json:"technologies,omitempty"`
	Geopolitical    []string  `json:"geopolitical,omitempty"`
	Sensitivity     []string  `json:"sensitivity,omitempty"`
	EvaluationStart time.Time `json:"evaluation_start,omitempty"`
	EvaluationEnd   time.Time `json:"evaluation_end,omitempty"`
}

// PolicyQueryResponse is returned by the policy discovery endpoint.
type PolicyQueryResponse struct {
	Target             TargetSummary          `json:"target"`
	ApplicablePolicies []PolicyWithDimensions  `json:"applicable_policies"`
}

// TargetSummary is a brief target representation in API responses.
type TargetSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Technologies []string `json:"technologies,omitempty"`
	Geopolitical []string `json:"geopolitical,omitempty"`
	Sensitivity  []string `json:"sensitivity,omitempty"`
	RegisteredAt string   `json:"registered_at"`
}

func policyQueryHandler(targets TargetStore, policies PolicyDimensionStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		targetID := c.QueryParam("target_id")
		if targetID == "" {
			return jsonError(c, http.StatusBadRequest, "missing target_id parameter")
		}

		timestampStr := c.QueryParam("timestamp")
		timestamp := time.Now().UTC()
		if timestampStr != "" {
			var err error
			timestamp, err = time.Parse(time.RFC3339, timestampStr)
			if err != nil {
				return jsonError(c, http.StatusBadRequest, "invalid timestamp format — expected RFC3339")
			}
		}

		ctx := c.Request().Context()

		target, err := targets.GetLatestTarget(ctx, targetID, timestamp)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to query target")
		}
		if target == nil {
			return jsonError(c, http.StatusNotFound, "target not found")
		}

		dims := DimensionQuery{
			Technologies: target.Technologies,
			Geopolitical: target.Geopolitical,
			Sensitivity:  target.Sensitivity,
			Users:        target.Users,
			Groups:       target.Groups,
			Timestamp:    timestamp,
		}

		matched, err := policies.QueryPoliciesByDimensions(ctx, dims)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to query policies")
		}
		if matched == nil {
			matched = []PolicyWithDimensions{}
		}

		resp := PolicyQueryResponse{
			Target: TargetSummary{
				ID:           target.TargetID,
				Name:         target.TargetName,
				Type:         target.TargetType,
				Technologies: target.Technologies,
				Geopolitical: target.Geopolitical,
				Sensitivity:  target.Sensitivity,
				RegisteredAt: target.RegisteredAt.Format(time.RFC3339),
			},
			ApplicablePolicies: matched,
		}

		return c.JSON(http.StatusOK, resp)
	}
}

func listTargetsHandler(targets TargetStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		all, err := targets.ListTargets(ctx)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to list targets")
		}
		if all == nil {
			all = []TargetRow{}
		}
		return c.JSON(http.StatusOK, all)
	}
}

func arraysOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if set[v] {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Add missing import for context**

Add `"context"` to the import block in `handlers_targets.go`.

- [ ] **Step 5: Register target routes in handlers.go**

In `internal/store/handlers.go`, add to the `Register` function:

```go
func Register(g *echo.Group, s Stores) {
	// ... existing registrations ...
	registerTargetRoutes(g, s)
}
```

Also add the `PolicyDimensions` field to the `Stores` struct:

```go
type Stores struct {
	// ... existing fields ...
	PolicyDimensions PolicyDimensionStore
}
```

- [ ] **Step 6: Implement QueryPoliciesByDimensions on Store**

Add to `internal/store/store.go`:

```go
func (s *Store) QueryPoliciesByDimensions(ctx context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error) {
	const q = `SELECT policy_id, title, version, tessera_log_index,
		technologies, geopolitical, sensitivity,
		evaluation_timeline_start, evaluation_timeline_end
	FROM policies
	WHERE (
		technologies && $1
		OR geopolitical && $2
		OR sensitivity && $3
		OR users && $4
		OR groups && $5
	)
	AND (evaluation_timeline_start IS NULL OR evaluation_timeline_start <= $6)
	AND (evaluation_timeline_end IS NULL OR evaluation_timeline_end >= $6)
	ORDER BY tessera_log_index ASC`

	rows, err := s.pool.Query(ctx, q,
		dims.Technologies, dims.Geopolitical, dims.Sensitivity,
		dims.Users, dims.Groups, dims.Timestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("query policies by dimensions: %w", err)
	}
	defer rows.Close()

	var out []PolicyWithDimensions
	for rows.Next() {
		var p PolicyWithDimensions
		var logIndex *int64
		if err := rows.Scan(
			&p.PolicyID, &p.Title, &p.Version, &logIndex,
			&p.Technologies, &p.Geopolitical, &p.Sensitivity,
			&p.EvaluationStart, &p.EvaluationEnd,
		); err != nil {
			return nil, fmt.Errorf("scan policy dimension row: %w", err)
		}
		if logIndex != nil {
			p.LogIndex = uint64(*logIndex)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
```

Add the compile-time interface check:

```go
var _ PolicyDimensionStore = (*Store)(nil)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/store -v -run TestPolicyQueryHandler`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/store/handlers_targets.go internal/store/handlers_targets_test.go internal/store/handlers.go internal/store/store.go
git commit -m "feat: add policy discovery API with dimension matching

- GET /api/policies/discover?target_id=X&timestamp=Y
- GET /api/targets for listing registered targets
- Dimension overlap matching (technologies, geopolitical, sensitivity)
- Temporal filtering by evaluation_timeline
- PolicyDimensionStore interface with PostgreSQL implementation

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Update Import API to Route Through Tessera

**Files:**
- Modify: `internal/store/handlers_import.go`

- [ ] **Step 1: Update ociImport to route through Tessera**

Replace the `ociImport` function in `internal/store/handlers_import.go`:

```go
func ociImport(c echo.Context, s Stores, ref string) error {
	if s.Registry == nil {
		return jsonError(c, http.StatusServiceUnavailable, "registry not configured")
	}

	repo, err := s.Registry.Repository(ref)
	if err != nil {
		return jsonError(c, http.StatusForbidden, err.Error())
	}

	ctx := c.Request().Context()
	bundle, err := gemarabundle.Unpack(ctx, repo, repo.Reference.Reference)
	if err != nil {
		slog.Error("oci import unpack failed", "reference", ref, "error", err)
		return jsonError(c, http.StatusBadGateway, "failed to pull bundle: "+err.Error())
	}

	bundleID := uuid.New().String()
	allFiles := append(bundle.Files, bundle.Imports...)

	if s.TesseraAppender == nil || s.IngestPublisher == nil {
		// Fallback: no Tessera configured, use legacy sync import
		return ociImportLegacy(c, s, allFiles, bundle.Etag)
	}

	// Build publisher identity from request context
	identity := events.PublisherIdentity{
		Sub:      "import:" + ref,
		Issuer:   "complytime-gateway",
		Type:     "import",
		Verified: true,
	}

	var imported []ociImportedArtifact
	for _, f := range allFiles {
		detected, err := gemara.DetectType(f.Data)
		if err != nil {
			slog.Warn("skip unrecognized artifact", "name", f.Name, "error", err)
			continue
		}

		logIndex, err := s.TesseraAppender.Add(ctx, f.Data)
		if err != nil {
			slog.Error("tessera append failed", "name", f.Name, "error", err)
			continue
		}

		jobID := uuid.New().String()
		s.IngestTracker.Create(jobID)

		if err := s.IngestPublisher.PublishIngestRawWithContext(
			jobID, f.Data, logIndex, identity,
		); err != nil {
			slog.Error("nats publish failed", "name", f.Name, "error", err)
		}

		imported = append(imported, ociImportedArtifact{
			Type: detected.String(),
			Name: f.Name,
		})
	}

	return c.JSON(http.StatusAccepted, map[string]any{
		"bundle_id": bundleID,
		"status":    "processing",
		"digest":    bundle.Etag,
		"artifacts": len(imported),
	})
}

// ociImportLegacy handles import when Tessera is not configured (backward compat).
func ociImportLegacy(c echo.Context, s Stores, files []gemarabundle.File, etag string) error {
	var resp ociImportResponse
	resp.Digest = etag

	ctx := c.Request().Context()
	for _, f := range files {
		art, err := storeArtifactFile(ctx, s, f)
		if err != nil {
			slog.Warn("import artifact failed", "name", f.Name, "error", err)
			continue
		}
		resp.Imported = append(resp.Imported, art)
	}

	if len(resp.Imported) == 0 {
		return jsonError(c, http.StatusBadRequest, "bundle contained no importable artifacts")
	}

	return c.JSON(http.StatusCreated, resp)
}
```

- [ ] **Step 2: Add required imports**

Add to import block:

```go
"github.com/complytime-labs/complytime-core/internal/events"
```

- [ ] **Step 3: Build to verify compilation**

Run: `go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add internal/store/handlers_import.go
git commit -m "feat: route OCI import through Tessera transparency log

- Each artifact in bundle gets tessera_log_index via /api/ingest flow
- Generates bundle_id linking all artifacts
- Returns 202 Accepted (async) instead of 201 Created (sync)
- Falls back to legacy sync import when Tessera not configured
- Publisher identity set to import:{oci_reference}

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Wire Gateway — Connect TargetStore and PolicyDimensions

**Files:**
- Modify: `cmd/gateway/main.go`

- [ ] **Step 1: Add Targets and PolicyDimensions to Stores initialization**

In `cmd/gateway/main.go`, update the Stores struct initialization (around line 137-161):

```go
stores := store.Stores{
	// ... existing fields ...
	Targets:          st,
	PolicyDimensions: st,
}
```

- [ ] **Step 2: Build to verify**

Run: `go build ./cmd/gateway`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
git add cmd/gateway/main.go
git commit -m "feat: wire TargetStore and PolicyDimensions in gateway

Connects target registration and policy dimension queries to the
gateway's Stores struct so the enrollment API endpoints are active.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Build and Verify All Tests Pass

- [ ] **Step 1: Run all existing tests**

Run: `go test ./... 2>&1 | tail -30`
Expected: All tests pass (some may skip due to missing POSTGRES_TEST_URL)

- [ ] **Step 2: Run witness tests specifically**

Run: `go test ./cmd/witness -v`
Expected: All 25 witness tests pass

- [ ] **Step 3: Build all binaries**

Run: `go build ./cmd/gateway && go build ./cmd/witness`
Expected: Both binaries build successfully

- [ ] **Step 4: Run go vet**

Run: `go vet ./...`
Expected: No warnings

- [ ] **Step 5: Commit any fixes**

If any issues found, fix and commit:

```bash
git add -A
git commit -m "fix: resolve build issues from policy enrollment implementation

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | Targets table migration | 1 new migration |
| 2 | Bundle artifacts table migration | 1 new migration |
| 3 | Policy dimension columns migration | 1 new migration |
| 4 | TargetStore interface + implementation | store.go |
| 5 | NATS events (PolicyEvent, TargetRegisteredEvent) | nats.go |
| 6 | IngestWorker TargetRegistration handling | ingest_worker.go, ingest_handler.go, handlers.go |
| 7 | Policy query API with dimension matching | handlers_targets.go (new) |
| 8 | Import API routes through Tessera | handlers_import.go |
| 9 | Gateway wiring | main.go |
| 10 | Build verification | All files |
