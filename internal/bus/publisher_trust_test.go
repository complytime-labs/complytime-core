// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/requirements"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestNATS(t *testing.T) *server.Server {
	t.Helper()
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		NoLog:     true,
		NoSigs:    true,
		JetStream: true,
		StoreDir:  t.TempDir(),
	}
	ns, err := server.NewServer(opts)
	require.NoError(t, err)
	go ns.Start()
	require.True(t, ns.ReadyForConnections(5*time.Second))
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	return ns
}

func connectTestJS(t *testing.T, ns *server.Server) jetstream.JetStream {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	return js
}

func TestPublisherTrustKV_InsertAndGet(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	rows := []requirements.TrustedPublisherRow{
		{
			TargetID:   "target-1",
			Issuer:     "https://token.actions.githubusercontent.com",
			SubPattern: "repo:org/repo",
			AddedAt:    time.Now(),
		},
		{
			TargetID:   "target-1",
			Issuer:     "https://token.actions.githubusercontent.com",
			SubPattern: "repo:org/other-repo",
			AddedAt:    time.Now(),
		},
	}

	err = store.InsertTrustedPublishers(ctx, rows)
	require.NoError(t, err)

	got, err := store.GetTrustedPublishers(ctx, "target-1")
	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Equal(t, "repo:org/repo", got[0].SubPattern)
	assert.Equal(t, "repo:org/other-repo", got[1].SubPattern)
}

func TestPublisherTrustKV_GetEmpty(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	got, err := store.GetTrustedPublishers(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPublisherTrustKV_Remove(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	rows := []requirements.TrustedPublisherRow{
		{
			TargetID:   "target-1",
			Issuer:     "https://issuer.example.com",
			SubPattern: "repo:org/repo",
			AddedAt:    time.Now(),
		},
		{
			TargetID:   "target-1",
			Issuer:     "https://issuer.example.com",
			SubPattern: "repo:org/keep-this",
			AddedAt:    time.Now(),
		},
	}
	require.NoError(t, store.InsertTrustedPublishers(ctx, rows))

	keys := []requirements.TrustedPublisherKey{
		{Issuer: "https://issuer.example.com", SubPattern: "repo:org/repo"},
	}
	err = store.RemoveTrustedPublishers(ctx, "target-1", keys, 42)
	require.NoError(t, err)

	got, err := store.GetTrustedPublishers(ctx, "target-1")
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, "repo:org/keep-this", got[0].SubPattern)
}

func TestPublisherTrustKV_UpsertOverwrite(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	env1 := "staging"
	row1 := []requirements.TrustedPublisherRow{
		{
			TargetID:    "target-1",
			Issuer:      "https://issuer.example.com",
			SubPattern:  "repo:org/repo",
			Environment: &env1,
			AddedAt:     time.Now(),
		},
	}
	require.NoError(t, store.InsertTrustedPublishers(ctx, row1))

	env2 := "production"
	row2 := []requirements.TrustedPublisherRow{
		{
			TargetID:    "target-1",
			Issuer:      "https://issuer.example.com",
			SubPattern:  "repo:org/repo",
			Environment: &env2,
			AddedAt:     time.Now(),
		},
	}
	require.NoError(t, store.InsertTrustedPublishers(ctx, row2))

	got, err := store.GetTrustedPublishers(ctx, "target-1")
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, "production", *got[0].Environment)
}

func TestPublisherTrustKV_MultipleTargets(t *testing.T) {
	ns := startTestNATS(t)
	js := connectTestJS(t, ns)
	ctx := context.Background()

	store, err := NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	rows := []requirements.TrustedPublisherRow{
		{TargetID: "target-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/a", AddedAt: time.Now()},
		{TargetID: "target-2", Issuer: "https://issuer.example.com", SubPattern: "repo:org/b", AddedAt: time.Now()},
	}
	require.NoError(t, store.InsertTrustedPublishers(ctx, rows))

	got1, err := store.GetTrustedPublishers(ctx, "target-1")
	require.NoError(t, err)
	assert.Len(t, got1, 1)
	assert.Equal(t, "repo:org/a", got1[0].SubPattern)

	got2, err := store.GetTrustedPublishers(ctx, "target-2")
	require.NoError(t, err)
	assert.Len(t, got2, 1)
	assert.Equal(t, "repo:org/b", got2[0].SubPattern)
}
