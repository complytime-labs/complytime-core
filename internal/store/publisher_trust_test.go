// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func pubTrustTestNATS(t *testing.T) jetstream.JetStream {
	t.Helper()
	opts := &server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: t.TempDir(),
	}
	ns, err := server.NewServer(opts)
	require.NoError(t, err)
	go ns.Start()
	require.True(t, ns.ReadyForConnections(5*time.Second))
	t.Cleanup(func() { ns.Shutdown(); ns.WaitForShutdown() })
	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	return js
}

func TestCheckPublisherTrust_Authorized(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	require.NoError(t, store.InsertTrustedPublishers(ctx, []requirements.TrustedPublisherRow{
		{TargetID: "tgt-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/repo", AddedAt: time.Now()},
	}))

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-1\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:org/repo"}

	err = checkPublisherTrust(ctx, body, claims, store)
	assert.NoError(t, err)
}

func TestCheckPublisherTrust_Unauthorized(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	require.NoError(t, store.InsertTrustedPublishers(ctx, []requirements.TrustedPublisherRow{
		{TargetID: "tgt-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/repo", AddedAt: time.Now()},
	}))

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-1\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:evil/attacker"}

	err = checkPublisherTrust(ctx, body, claims, store)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestCheckPublisherTrust_GlobMatch(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	require.NoError(t, store.InsertTrustedPublishers(ctx, []requirements.TrustedPublisherRow{
		{TargetID: "tgt-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/*", AddedAt: time.Now()},
	}))

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-1\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:org/any-repo"}

	err = checkPublisherTrust(ctx, body, claims, store)
	assert.NoError(t, err)
}

func TestCheckPublisherTrust_NoTargetID_Skips(t *testing.T) {
	body := []byte("metadata:\n  type: Policy\n  id: my-policy\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	err := checkPublisherTrust(context.Background(), body, claims, nil)
	assert.NoError(t, err)
}

func TestCheckPublisherTrust_TargetRegistration_Skips(t *testing.T) {
	body := []byte("metadata:\n  type: TargetRegistration\ntarget:\n  id: tgt-1\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	err := checkPublisherTrust(context.Background(), body, claims, nil)
	assert.NoError(t, err)
}

func TestCheckPublisherTrust_EmptyAllowlist_Denies(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-no-publishers\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	err = checkPublisherTrust(ctx, body, claims, store)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no trusted publishers configured")
}

func TestMatchPublisher_ExactMatch(t *testing.T) {
	assert.True(t, matchPublisher("https://iss.com", "repo:org/repo", "https://iss.com", "repo:org/repo"))
	assert.False(t, matchPublisher("https://iss.com", "repo:org/repo", "https://other.com", "repo:org/repo"))
	assert.False(t, matchPublisher("https://iss.com", "repo:org/repo", "https://iss.com", "repo:org/other"))
}

func TestMatchPublisher_GlobMatch(t *testing.T) {
	assert.True(t, matchPublisher("https://iss.com", "repo:org/repo", "https://iss.com", "repo:org/*"))
	assert.True(t, matchPublisher("https://iss.com", "repo:org/anything", "https://iss.com", "repo:org/*"))
	assert.False(t, matchPublisher("https://iss.com", "repo:other/repo", "https://iss.com", "repo:org/*"))
}
