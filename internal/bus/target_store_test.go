// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/requirements"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTargetStoreKV_InsertAndGet(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewTargetStoreKV(ctx, js)
	require.NoError(t, err)

	row := requirements.TargetRow{
		TargetID:     "tgt-001",
		TargetName:   "My Application",
		TargetType:   "Software",
		RegisteredAt: time.Now().Truncate(time.Millisecond),
		RegisteredBy: "smoke-test@complytime.dev",
	}

	err = store.InsertTarget(ctx, row)
	require.NoError(t, err)

	got, err := store.GetLatestTarget(ctx, "tgt-001", time.Now())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tgt-001", got.TargetID)
	assert.Equal(t, "My Application", got.TargetName)
	assert.Equal(t, "Software", got.TargetType)
}

func TestTargetStoreKV_GetNotFound(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewTargetStoreKV(ctx, js)
	require.NoError(t, err)

	got, err := store.GetLatestTarget(ctx, "nonexistent", time.Now())
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestTargetStoreKV_ListTargets(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewTargetStoreKV(ctx, js)
	require.NoError(t, err)

	targets := []requirements.TargetRow{
		{TargetID: "tgt-001", TargetName: "App A", TargetType: "Software", RegisteredAt: time.Now()},
		{TargetID: "tgt-002", TargetName: "App B", TargetType: "Software", RegisteredAt: time.Now()},
	}
	for _, tgt := range targets {
		require.NoError(t, store.InsertTarget(ctx, tgt))
	}

	got, err := store.ListTargets(ctx)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestTargetStoreKV_UpsertOverwrite(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewTargetStoreKV(ctx, js)
	require.NoError(t, err)

	row1 := requirements.TargetRow{
		TargetID:   "tgt-001",
		TargetName: "Old Name",
		TargetType: "Software",
	}
	require.NoError(t, store.InsertTarget(ctx, row1))

	row2 := requirements.TargetRow{
		TargetID:   "tgt-001",
		TargetName: "New Name",
		TargetType: "Software",
	}
	require.NoError(t, store.InsertTarget(ctx, row2))

	got, err := store.GetLatestTarget(ctx, "tgt-001", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "New Name", got.TargetName)
}
