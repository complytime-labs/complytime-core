// SPDX-License-Identifier: Apache-2.0

package events_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngestRef_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	original := events.IngestRef{
		JobID:    "job-123",
		LogIndex: 42,
		PublisherIdentity: events.PublisherIdentity{
			Sub:      "repo:complytime/scanner:ref:refs/heads/main",
			Issuer:   "https://token.actions.githubusercontent.com",
			Type:     "pipeline",
			Verified: true,
		},
		Timestamp: now,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded events.IngestRef
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.LogIndex, decoded.LogIndex)
	assert.Equal(t, original.PublisherIdentity, decoded.PublisherIdentity)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestIngestRef_WithBundleFields(t *testing.T) {
	now := time.Now().UTC()
	original := events.IngestRef{
		JobID:    "job-bundle",
		LogIndex: 99,
		PublisherIdentity: events.PublisherIdentity{
			Sub:      "import:ghcr.io/org/policy:v1",
			Issuer:   "complytime-gateway",
			Type:     "import",
			Verified: true,
		},
		BundleID:     "bundle-abc",
		OCIReference: "ghcr.io/org/policy:v1",
		Timestamp:    now,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded events.IngestRef
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BundleID, decoded.BundleID)
	assert.Equal(t, original.OCIReference, decoded.OCIReference)
}

func TestPublisherIdentity_JSONSerialization(t *testing.T) {
	original := events.PublisherIdentity{
		Sub:      "repo:complytime/scanner:ref:refs/heads/main",
		Issuer:   "https://token.actions.githubusercontent.com",
		Type:     "pipeline",
		Verified: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded events.PublisherIdentity
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Sub, decoded.Sub)
	assert.Equal(t, original.Issuer, decoded.Issuer)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Verified, decoded.Verified)
}

func TestIngestRef_WithEmptyPublisherIdentity(t *testing.T) {
	original := events.IngestRef{
		JobID:             "job-456",
		LogIndex:          100,
		PublisherIdentity: events.PublisherIdentity{},
		Timestamp:         time.Now().UTC(),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded events.IngestRef
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.LogIndex, decoded.LogIndex)
	assert.Empty(t, decoded.PublisherIdentity.Sub)
	assert.Empty(t, decoded.PublisherIdentity.Issuer)
	assert.False(t, decoded.PublisherIdentity.Verified)
}
