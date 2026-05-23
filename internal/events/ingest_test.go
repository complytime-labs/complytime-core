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

func TestIngestRawEvent_JSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	original := events.IngestRawEvent{
		JobID:    "job-123",
		LogIndex: 42,
		YAML:     []byte("metadata:\n  type: EvaluationLog"),
		PublisherIdentity: events.PublisherIdentity{
			Sub:      "repo:complytime/scanner:ref:refs/heads/main",
			Issuer:   "https://token.actions.githubusercontent.com",
			Type:     "pipeline",
			Verified: true,
		},
		Timestamp: now,
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize from JSON
	var decoded events.IngestRawEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify round-trip
	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.LogIndex, decoded.LogIndex)
	assert.Equal(t, original.YAML, decoded.YAML)
	assert.Equal(t, original.PublisherIdentity, decoded.PublisherIdentity)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestPublisherIdentity_JSONSerialization(t *testing.T) {
	original := events.PublisherIdentity{
		Sub:      "repo:complytime/scanner:ref:refs/heads/main",
		Issuer:   "https://token.actions.githubusercontent.com",
		Type:     "pipeline",
		Verified: true,
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize from JSON
	var decoded events.PublisherIdentity
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify round-trip
	assert.Equal(t, original.Sub, decoded.Sub)
	assert.Equal(t, original.Issuer, decoded.Issuer)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Verified, decoded.Verified)
}

func TestIngestRawEvent_WithEmptyPublisherIdentity(t *testing.T) {
	original := events.IngestRawEvent{
		JobID:    "job-456",
		LogIndex: 100,
		YAML:     []byte("test"),
		PublisherIdentity: events.PublisherIdentity{}, // Empty/zero values
		Timestamp: time.Now().UTC(),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded events.IngestRawEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.LogIndex, decoded.LogIndex)
	assert.Equal(t, original.PublisherIdentity.Sub, decoded.PublisherIdentity.Sub)
	assert.Equal(t, original.PublisherIdentity.Issuer, decoded.PublisherIdentity.Issuer)
	assert.Equal(t, original.PublisherIdentity.Type, decoded.PublisherIdentity.Type)
	assert.Equal(t, original.PublisherIdentity.Verified, decoded.PublisherIdentity.Verified)
}
