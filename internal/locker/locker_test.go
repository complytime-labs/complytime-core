package locker_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/locker"
)

func TestLocker_CreateAndGetLedger(t *testing.T) {
	ctx := context.Background()
	lkr, err := locker.NewLocker(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { lkr.Close(ctx) })

	// Create a ledger
	ledger, err := lkr.CreateLedger(ctx, "subject-alpha")
	require.NoError(t, err)
	assert.NotNil(t, ledger)
	assert.Equal(t, "subject-alpha", ledger.SubjectID())

	// Get it back
	got, ok := lkr.GetLedger("subject-alpha")
	assert.True(t, ok)
	assert.Equal(t, ledger, got)

	// Unknown subject
	_, ok = lkr.GetLedger("unknown")
	assert.False(t, ok)
}

func TestLocker_CreateDuplicateFails(t *testing.T) {
	ctx := context.Background()
	lkr, err := locker.NewLocker(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { lkr.Close(ctx) })

	_, err = lkr.CreateLedger(ctx, "subject-alpha")
	require.NoError(t, err)

	_, err = lkr.CreateLedger(ctx, "subject-alpha")
	assert.Error(t, err)
}

func TestLocker_MultipleLedgersIndependent(t *testing.T) {
	ctx := context.Background()
	lkr, err := locker.NewLocker(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { lkr.Close(ctx) })

	la, err := lkr.CreateLedger(ctx, "alpha")
	require.NoError(t, err)
	lb, err := lkr.CreateLedger(ctx, "beta")
	require.NoError(t, err)

	// Seal into alpha
	idx, err := la.Seal(ctx, []byte("alpha-receipt"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), idx)

	// Seal into beta — also gets index 0 (independent log)
	idx, err = lb.Seal(ctx, []byte("beta-receipt"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), idx)

	// Fetch from each
	data, err := la.Fetch(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-receipt"), data)

	data, err = lb.Fetch(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("beta-receipt"), data)

	// Verifier keys are different
	assert.NotEqual(t, la.VerifierKey(), lb.VerifierKey())
}

func TestLocker_OpensExistingLedgersOnStartup(t *testing.T) {
	ctx := context.Background()
	basePath := t.TempDir()

	// Create a locker with a ledger and seal something
	lkr1, err := locker.NewLocker(basePath)
	require.NoError(t, err)

	ledger, err := lkr1.CreateLedger(ctx, "persist-test")
	require.NoError(t, err)
	_, err = ledger.Seal(ctx, []byte("persisted-receipt"))
	require.NoError(t, err)
	require.NoError(t, lkr1.Close(ctx))

	// Create a new locker on the same path — should find existing ledger
	lkr2, err := locker.NewLocker(basePath)
	require.NoError(t, err)
	t.Cleanup(func() { lkr2.Close(ctx) })

	err = lkr2.OpenExistingLedgers(ctx)
	require.NoError(t, err)

	got, ok := lkr2.GetLedger("persist-test")
	require.True(t, ok)

	data, err := got.Fetch(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte("persisted-receipt"), data)
}
