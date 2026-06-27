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

	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:org/repo"}

	trusted, err := isPublisherTrusted(ctx, claims, "tgt-1", store)
	assert.NoError(t, err)
	assert.True(t, trusted)
}

func TestCheckPublisherTrust_Unauthorized(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	require.NoError(t, store.InsertTrustedPublishers(ctx, []requirements.TrustedPublisherRow{
		{TargetID: "tgt-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/repo", AddedAt: time.Now()},
	}))

	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:evil/attacker"}

	trusted, err := isPublisherTrusted(ctx, claims, "tgt-1", store)
	assert.Error(t, err)
	assert.False(t, trusted)
	assert.Contains(t, err.Error(), "publisher https://issuer.example.com/repo:evil/attacker is not trusted for target tgt-1")
}

func TestCheckPublisherTrust_GlobMatch(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	require.NoError(t, store.InsertTrustedPublishers(ctx, []requirements.TrustedPublisherRow{
		{TargetID: "tgt-1", Issuer: "https://issuer.example.com", SubPattern: "repo:org/*", AddedAt: time.Now()},
	}))

	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "repo:org/any-repo"}

	trusted, err := isPublisherTrusted(ctx, claims, "tgt-1", store)
	assert.NoError(t, err)
	assert.True(t, trusted)
}

func TestResolvePublishAction_NoTargetID_ReturnsPolicy(t *testing.T) {
	body := []byte("metadata:\n  type: EvaluationLog\n  id: my-eval\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	action, attrs, err := resolvePublishAction(context.Background(), body, claims, nil)
	assert.NoError(t, err)
	assert.Equal(t, "publish:policy", action.ID.String())
	assert.Nil(t, attrs)
}

func TestResolvePublishAction_TargetRegistration_ReturnsRegistration(t *testing.T) {
	body := []byte("metadata:\n  type: TargetRegistration\ntarget:\n  id: tgt-1\n")
	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	action, attrs, err := resolvePublishAction(context.Background(), body, claims, nil)
	assert.NoError(t, err)
	assert.Equal(t, "admin:register-target", action.ID.String())
	assert.Nil(t, attrs)
}

func TestCheckPublisherTrust_EmptyAllowlist_Denies(t *testing.T) {
	js := pubTrustTestNATS(t)
	ctx := context.Background()
	store, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	claims := &auth.JWTClaims{Iss: "https://issuer.example.com", Sub: "anyone"}

	trusted, err := isPublisherTrusted(ctx, claims, "tgt-no-publishers", store)
	assert.Error(t, err)
	assert.False(t, trusted)
	assert.Contains(t, err.Error(), "no trusted publishers configured for target tgt-no-publishers")
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
