// internal/tessera/client_test.go
package tessera_test

import (
	"context"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/tessera"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Add_SequentialIndices(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Use short checkpoint time for tests
	opts := tessera.Options{
		CheckpointTime: 100 * time.Millisecond,
		CheckpointSize: 100,
	}
	client, err := tessera.NewClient(ctx, tmpDir, opts)
	require.NoError(t, err)
	defer client.Close()

	// Add first entry
	idx1, err := client.Add(ctx, []byte("entry 1"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), idx1)

	// Add second entry
	idx2, err := client.Add(ctx, []byte("entry 2"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), idx2)

	// Add third entry
	idx3, err := client.Add(ctx, []byte("entry 3"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), idx3)
}

func TestClient_Read_ReturnsStoredEntry(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Use short checkpoint time for tests
	opts := tessera.Options{
		CheckpointTime: 100 * time.Millisecond,
		CheckpointSize: 100,
	}
	client, err := tessera.NewClient(ctx, tmpDir, opts)
	require.NoError(t, err)
	defer client.Close()

	// Add entry
	entry := []byte("test evidence yaml")
	idx, err := client.Add(ctx, entry)
	require.NoError(t, err)

	// Wait for entry to be integrated into the log
	// Entries are durably sequenced immediately but need time to be integrated and published
	// DefaultBatchMaxAge is 250ms, and checkpoint interval is also 100ms in test defaults
	time.Sleep(2 * time.Second)

	// Read entry back
	retrieved, err := client.Read(ctx, idx)
	require.NoError(t, err)
	assert.Equal(t, entry, retrieved)
}
