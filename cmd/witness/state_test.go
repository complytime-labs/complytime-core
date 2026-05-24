// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState_SaveAndLoad(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "witness-state-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Create state
	original := &State{
		LastVerifiedIndex:  12345,
		LastCheckpointHash: "sha256:abc123def456",
		UpdatedAt:          time.Now().UTC().Truncate(time.Second),
	}

	// Save
	err = SaveState(tmpfile.Name(), original)
	require.NoError(t, err)

	// Load
	loaded, err := LoadState(tmpfile.Name())
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.LastVerifiedIndex, loaded.LastVerifiedIndex)
	assert.Equal(t, original.LastCheckpointHash, loaded.LastCheckpointHash)
	assert.Equal(t, original.UpdatedAt.Unix(), loaded.UpdatedAt.Unix())
}

func TestState_LoadNonexistent_ReturnsZeroState(t *testing.T) {
	state, err := LoadState("/nonexistent/state.json")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), state.LastVerifiedIndex)
	assert.Empty(t, state.LastCheckpointHash)
}
