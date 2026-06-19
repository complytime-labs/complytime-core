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
	defer func() { _ = client.Close() }()

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

func TestClient_PersistentSignerKey(t *testing.T) {
	ctx := context.Background()
	storageDir := t.TempDir()
	keyPath := storageDir + "/signer.key"

	opts := tessera.Options{
		CheckpointTime: 100 * time.Millisecond,
		CheckpointSize: 100,
		SignerKeyPath:  keyPath,
	}

	// Create first client — this generates and persists the key
	client1, err := tessera.NewClient(ctx, storageDir+"/log", opts)
	require.NoError(t, err)
	require.NoError(t, client1.Close())

	// Create second client — should reuse the same key
	client2, err := tessera.NewClient(ctx, storageDir+"/log", opts)
	require.NoError(t, err)
	require.NoError(t, client2.Close())

	// The key file should still exist and be valid
	skey, vkey, generated, err := tessera.LoadOrGenerateSignerKey(keyPath)
	require.NoError(t, err)
	assert.False(t, generated, "existing key should be loaded, not generated")
	assert.Contains(t, skey, "PRIVATE+KEY+")
	assert.NotEmpty(t, vkey)
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
	defer func() { _ = client.Close() }()

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
