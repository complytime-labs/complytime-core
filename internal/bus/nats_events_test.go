package bus

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyEvent_JSON(t *testing.T) {
	evt := PolicyEvent{
		LogIndex:  42,
		PolicyID:  "infra-security-baseline",
		Timestamp: time.Now().UTC(),
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

func TestIngestRef_Contract(t *testing.T) {
	ref := IngestRef{
		JobID:    "550e8400-e29b-41d4-a716-446655440000",
		LogIndex: 7,
		PublisherIdentity: PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:complytime-labs/complytime-core:ref:refs/heads/main",
			Type:     "pipeline",
			Verified: true,
		},
		Timestamp: time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(ref)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "job_id")
	assert.Contains(t, raw, "log_index")
	assert.Contains(t, raw, "publisher_identity")
	assert.Contains(t, raw, "timestamp")

	pi := raw["publisher_identity"].(map[string]any)
	assert.Contains(t, pi, "issuer")
	assert.Contains(t, pi, "sub")
	assert.Contains(t, pi, "type")
	assert.Contains(t, pi, "verified")

	var decoded IngestRef
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, ref.JobID, decoded.JobID)
	assert.Equal(t, ref.LogIndex, decoded.LogIndex)
	assert.Equal(t, ref.PublisherIdentity.Issuer, decoded.PublisherIdentity.Issuer)
	assert.Equal(t, ref.PublisherIdentity.Sub, decoded.PublisherIdentity.Sub)
	assert.Equal(t, ref.PublisherIdentity.Type, decoded.PublisherIdentity.Type)
	assert.True(t, decoded.PublisherIdentity.Verified)

	assert.NotContains(t, raw, "bundle_id", "omitempty fields should be absent when empty")
	assert.NotContains(t, raw, "oci_reference", "omitempty fields should be absent when empty")
}

func TestIngestRef_WithBundleFields_Contract(t *testing.T) {
	ref := IngestRef{
		JobID:    "test-bundle-job",
		LogIndex: 3,
		PublisherIdentity: PublisherIdentity{
			Issuer: "https://issuer.example.com",
			Sub:    "import:ghcr.io/org/bundle:v1",
			Type:   "import",
		},
		BundleID:     "bundle-001",
		OCIReference: "ghcr.io/org/bundle:v1",
		Timestamp:    time.Now().UTC(),
	}

	data, err := json.Marshal(ref)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "bundle_id")
	assert.Contains(t, raw, "oci_reference")
	assert.Equal(t, "bundle-001", raw["bundle_id"])
	assert.Equal(t, "ghcr.io/org/bundle:v1", raw["oci_reference"])
}

func TestTargetRegisteredEvent_JSON(t *testing.T) {
	evt := TargetRegisteredEvent{
		LogIndex:     15,
		TargetID:     "prod-cluster",
		RegisteredBy: "repo:org/infra:ref:refs/heads/main",
		Timestamp:    time.Now().UTC(),
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
