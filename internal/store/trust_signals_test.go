package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/certifier"
	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInsertAndQueryTrustSignals verifies that trust signals can be inserted and queried.
func TestInsertAndQueryTrustSignals(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("POSTGRES_TEST_URL") == "" {
		t.Skip("Skipping test: POSTGRES_TEST_URL not set")
	}

	ctx := context.Background()
	pgURL := os.Getenv("POSTGRES_TEST_URL")

	// Connect to test database
	pgClient, err := postgres.New(ctx, postgres.Config{URL: pgURL})
	require.NoError(t, err)
	defer pgClient.Close()

	// Run migrations
	err = pgClient.EnsureSchema(ctx)
	require.NoError(t, err)

	st := New(pgClient.Pool())

	// Clean up test data scoped to this test only — avoid TRUNCATE evidence
	// which races with E2E tests running in a parallel package.
	_, err = pgClient.Pool().Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id LIKE 'test-evidence-ts-%'")
	require.NoError(t, err)
	_, err = pgClient.Pool().Exec(ctx, "DELETE FROM evidence WHERE evidence_id LIKE 'test-evidence-ts-%'")
	require.NoError(t, err)

	// Insert test evidence
	evidenceID := "test-evidence-ts-001"
	_, err = st.InsertEvidence(ctx, []EvidenceRecord{
		{
			EvidenceID:       evidenceID,
			PolicyID:         "test-policy",
			TargetID:         "test-target",
			RuleID:           "test-rule",
			ControlID:        "test-control",
			RequirementID:    "test-req",
			EvalResult:       "Passed",
			ComplianceStatus: "Compliant",
			EnrichmentStatus: "Success",
			CollectedAt:      time.Now(),
		},
	})
	require.NoError(t, err)

	// Create test trust signals
	now := time.Now()
	signals := []TrustSignalRow{
		{
			EvidenceID: evidenceID,
			Layer:      "quality",
			CheckName:  "deployment-frequency",
			Result:     certifier.ResultPass,
			Reason:     "Deployment frequency meets threshold",
			CheckedAt:  now,
		},
		{
			EvidenceID: evidenceID,
			Layer:      "identity",
			CheckName:  "provenance",
			Result:     certifier.ResultPass,
			Reason:     "Valid provenance attestation",
			CheckedAt:  now,
		},
	}

	// Insert the trust signals
	err = st.InsertTrustSignals(ctx, signals)
	require.NoError(t, err)

	// Query the trust signals back
	rows, err := st.QueryTrustSignals(ctx, evidenceID)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "Expected 2 trust signals to be recorded")

	// Verify the signal details
	if len(rows) >= 2 {
		// Results are ordered by checked_at DESC
		sig0 := rows[0]
		sig1 := rows[1]

		assert.Equal(t, evidenceID, sig0.EvidenceID)
		assert.Equal(t, evidenceID, sig1.EvidenceID)

		// Check that we got both signals
		checkNames := map[string]bool{
			sig0.CheckName: true,
			sig1.CheckName: true,
		}
		assert.True(t, checkNames["deployment-frequency"], "Expected deployment-frequency signal")
		assert.True(t, checkNames["provenance"], "Expected provenance signal")
	}
}
