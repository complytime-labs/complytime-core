package gateway_test

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/gateway"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func startTestNATS(t *testing.T) *natsgo.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
	}
	ns, err := natsserver.NewServer(opts)
	require.NoError(t, err)
	ns.Start()
	t.Cleanup(ns.Shutdown)

	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}

	nc, err := natsgo.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	return nc
}

func TestTrustStore_UnknownSubjectReturnsNotTrusted(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	store, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	// Unknown subject should return not trusted
	trusted, err := store.IsPublisherTrusted(ctx, "unknown-subject", "https://issuer.example.com", "pub-123")
	require.NoError(t, err)
	assert.False(t, trusted)
}

func TestTrustStore_SetTrustAndVerify(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	store, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	subjectID := "test-subject"
	issuer := "https://issuer.example.com"
	sub := "pub-123"

	// Initially not trusted
	trusted, err := store.IsPublisherTrusted(ctx, subjectID, issuer, sub)
	require.NoError(t, err)
	assert.False(t, trusted)

	// Register subject
	err = store.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	// Set trust
	publishers := []gateway.TrustEntry{
		{Issuer: issuer, Sub: sub},
	}
	err = store.SetPublisherTrust(ctx, subjectID, publishers)
	require.NoError(t, err)

	// Now should be trusted
	trusted, err = store.IsPublisherTrusted(ctx, subjectID, issuer, sub)
	require.NoError(t, err)
	assert.True(t, trusted)
}

func TestTrustStore_WrongSubReturnsNotTrusted(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	store, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	subjectID := "test-subject"
	trustedIssuer := "https://issuer.example.com"
	trustedSub := "pub-123"
	wrongSub := "pub-456"

	// Register and set trust
	err = store.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	publishers := []gateway.TrustEntry{
		{Issuer: trustedIssuer, Sub: trustedSub},
	}
	err = store.SetPublisherTrust(ctx, subjectID, publishers)
	require.NoError(t, err)

	// Correct issuer/sub should be trusted
	trusted, err := store.IsPublisherTrusted(ctx, subjectID, trustedIssuer, trustedSub)
	require.NoError(t, err)
	assert.True(t, trusted)

	// Wrong sub should not be trusted
	trusted, err = store.IsPublisherTrusted(ctx, subjectID, trustedIssuer, wrongSub)
	require.NoError(t, err)
	assert.False(t, trusted)
}

func TestTrustStore_MultipleTrustedPublishers(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	store, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	subjectID := "test-subject"

	// Register and set trust for multiple publishers
	err = store.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	publishers := []gateway.TrustEntry{
		{Issuer: "https://issuer-a.example.com", Sub: "pub-a"},
		{Issuer: "https://issuer-b.example.com", Sub: "pub-b"},
	}
	err = store.SetPublisherTrust(ctx, subjectID, publishers)
	require.NoError(t, err)

	// Both should be trusted
	trusted, err := store.IsPublisherTrusted(ctx, subjectID, "https://issuer-a.example.com", "pub-a")
	require.NoError(t, err)
	assert.True(t, trusted)

	trusted, err = store.IsPublisherTrusted(ctx, subjectID, "https://issuer-b.example.com", "pub-b")
	require.NoError(t, err)
	assert.True(t, trusted)

	// Untrusted combination should fail
	trusted, err = store.IsPublisherTrusted(ctx, subjectID, "https://issuer-a.example.com", "pub-b")
	require.NoError(t, err)
	assert.False(t, trusted)
}

func TestTrustStore_UpdateTrustList(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	store, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	subjectID := "test-subject"

	// Register and set initial trust
	err = store.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	initialPublishers := []gateway.TrustEntry{
		{Issuer: "https://issuer.example.com", Sub: "pub-old"},
	}
	err = store.SetPublisherTrust(ctx, subjectID, initialPublishers)
	require.NoError(t, err)

	// Verify old is trusted
	trusted, err := store.IsPublisherTrusted(ctx, subjectID, "https://issuer.example.com", "pub-old")
	require.NoError(t, err)
	assert.True(t, trusted)

	// Update trust to new publisher
	newPublishers := []gateway.TrustEntry{
		{Issuer: "https://issuer.example.com", Sub: "pub-new"},
	}
	err = store.SetPublisherTrust(ctx, subjectID, newPublishers)
	require.NoError(t, err)

	// Old should no longer be trusted
	trusted, err = store.IsPublisherTrusted(ctx, subjectID, "https://issuer.example.com", "pub-old")
	require.NoError(t, err)
	assert.False(t, trusted)

	// New should be trusted
	trusted, err = store.IsPublisherTrusted(ctx, subjectID, "https://issuer.example.com", "pub-new")
	require.NoError(t, err)
	assert.True(t, trusted)
}
