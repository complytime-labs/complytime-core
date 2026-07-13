package locker_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/locker"
)

func TestLedger_SealAndFetch(t *testing.T) {
	ctx := context.Background()
	basePath := t.TempDir()

	ledger, err := locker.NewLedger(ctx, "test-subject", basePath)
	require.NoError(t, err)
	t.Cleanup(func() { ledger.Close(ctx) })

	receipt := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`)

	// Seal a receipt
	index, err := ledger.Seal(ctx, receipt)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), index)

	// Fetch it back
	got, err := ledger.Fetch(ctx, index)
	require.NoError(t, err)
	assert.Equal(t, receipt, got)

	// Seal another
	index2, err := ledger.Seal(ctx, []byte(`{"second":"entry"}`))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), index2)
}

func TestLedger_VerifyDigest(t *testing.T) {
	ctx := context.Background()
	basePath := t.TempDir()

	ledger, err := locker.NewLedger(ctx, "test-subject", basePath)
	require.NoError(t, err)
	t.Cleanup(func() { ledger.Close(ctx) })

	receipt := []byte(`{"test":"receipt"}`)
	_, err = ledger.Seal(ctx, receipt)
	require.NoError(t, err)

	// Compute expected digest
	digest := locker.SHA256Hex(receipt)

	// Verify by digest
	index, found := ledger.VerifyDigest(digest)
	assert.True(t, found)
	assert.Equal(t, uint64(0), index)

	// Unknown digest
	_, found = ledger.VerifyDigest("0000000000000000000000000000000000000000000000000000000000000000")
	assert.False(t, found)
}

func TestLedger_VerifierKey(t *testing.T) {
	ctx := context.Background()
	basePath := t.TempDir()

	ledger, err := locker.NewLedger(ctx, "test-subject", basePath)
	require.NoError(t, err)
	t.Cleanup(func() { ledger.Close(ctx) })

	key := ledger.VerifierKey()
	assert.NotEmpty(t, key)
	assert.Contains(t, key, "complytime/test-subject")
}
