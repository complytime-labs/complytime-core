package events

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
