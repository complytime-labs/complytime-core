package nats_test

import (
	"context"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestEnsureInfrastructure(t *testing.T) {
	nc := startTestNATS(t)
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()

	// First call creates everything
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Verify INGEST stream exists
	stream, err := js.Stream(ctx, natsinfra.StreamIngest)
	require.NoError(t, err)
	info, err := stream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, natsinfra.StreamIngest, info.Config.Name)
	assert.Equal(t, jetstream.WorkQueuePolicy, info.Config.Retention)
	assert.Equal(t, 2*time.Minute, info.Config.Duplicates)

	// Verify EVIDENCE stream exists
	evidenceStream, err := js.Stream(ctx, natsinfra.StreamEvidence)
	require.NoError(t, err)
	evidenceInfo, err := evidenceStream.Info(ctx)
	require.NoError(t, err)
	assert.Equal(t, natsinfra.StreamEvidence, evidenceInfo.Config.Name)
	assert.Contains(t, evidenceInfo.Config.Subjects, "core.evidence.>")
	assert.Equal(t, jetstream.InterestPolicy, evidenceInfo.Config.Retention)

	// Verify KV buckets exist
	ptKV, err := js.KeyValue(ctx, natsinfra.PublisherTrustBucket)
	require.NoError(t, err)
	ptStatus, err := ptKV.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, natsinfra.PublisherTrustBucket, ptStatus.Bucket())

	srKV, err := js.KeyValue(ctx, natsinfra.SubjectRegistryBucket)
	require.NoError(t, err)
	srStatus, err := srKV.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, natsinfra.SubjectRegistryBucket, srStatus.Bucket())

	// Second call is idempotent
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)
}

func TestEvidenceIngestedSubject(t *testing.T) {
	assert.Equal(t, "core.evidence.ingested.my-app", natsinfra.EvidenceIngestedSubject("my-app"))
}

func TestEvidenceSealedSubject(t *testing.T) {
	assert.Equal(t, "core.evidence.sealed.my-app", natsinfra.EvidenceSealedSubject("my-app"))
}
