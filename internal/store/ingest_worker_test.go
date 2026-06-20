// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/bus"
)

type staticReader struct {
	data map[uint64][]byte
}

func (r *staticReader) Read(_ context.Context, index uint64) ([]byte, error) {
	if d, ok := r.data[index]; ok {
		return d, nil
	}
	return nil, os.ErrNotExist
}

type recordingPublisher struct {
	evidenceCalls []string
	policyCalls   []uint64
	targetCalls   []string
}

func (p *recordingPublisher) PublishEvidence(policyID string, _ int) {
	p.evidenceCalls = append(p.evidenceCalls, policyID)
}
func (p *recordingPublisher) PublishDraftAuditLog(_, _, _ string) {}
func (p *recordingPublisher) PublishPolicyNew(logIndex uint64, _ string) {
	p.policyCalls = append(p.policyCalls, logIndex)
}
func (p *recordingPublisher) PublishTargetRegistered(_ uint64, targetID, _ string) {
	p.targetCalls = append(p.targetCalls, targetID)
}

func startIngestTestNATS(t *testing.T) jetstream.JetStream {
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
	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	require.NoError(t, err)
	return js
}

func TestIngestWorker_EvidencePublishesEvent(t *testing.T) {
	evalYAML, err := os.ReadFile("../../internal/e2e/testdata/evaluation_log_sample.yaml")
	require.NoError(t, err)

	reader := &staticReader{data: map[uint64][]byte{0: evalYAML}}
	pub := &recordingPublisher{}
	tracker := NewIngestTracker()

	js := startIngestTestNATS(t)
	ctx := context.Background()

	targetStore, err := bus.NewTargetStoreKV(ctx, js)
	require.NoError(t, err)
	pubTrust, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	stores := Stores{
		Targets:           targetStore,
		TrustedPublishers: pubTrust,
		EventPublisher:    pub,
		IngestTracker:     tracker,
	}

	tracker.Create("test-job-1")

	ref := bus.IngestRef{
		JobID:    "test-job-1",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer: "https://issuer.example.com",
			Sub:    "repo:org/repo",
			Type:   "pipeline",
		},
		Timestamp: time.Now(),
	}

	handler := IngestWorker(ctx, stores, pub, tracker, reader)

	mockMsg := &fakeJSMsg{acked: false}
	handler(ctx, ref, mockMsg)

	assert.True(t, mockMsg.acked, "message should be acked")
	assert.Len(t, pub.evidenceCalls, 1, "should publish one evidence event")

	status := tracker.Get("test-job-1")
	require.NotNil(t, status)
	assert.Equal(t, "completed", status.Status)
}

func TestIngestWorker_TargetRegistrationUpdatesKV(t *testing.T) {
	regYAML := []byte(`metadata:
  type: TargetRegistration
  id: reg-001
  date: "2026-06-19T00:00:00Z"
target:
  id: tgt-smoke
  name: Smoke Test Target
  type: Software
  trusted-publishers:
    - issuer: https://token.actions.githubusercontent.com
      sub_pattern: "repo:org/repo"
`)

	reader := &staticReader{data: map[uint64][]byte{0: regYAML}}
	pub := &recordingPublisher{}
	tracker := NewIngestTracker()

	js := startIngestTestNATS(t)
	ctx := context.Background()

	targetStore, err := bus.NewTargetStoreKV(ctx, js)
	require.NoError(t, err)
	pubTrust, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	stores := Stores{
		Targets:           targetStore,
		TrustedPublishers: pubTrust,
		EventPublisher:    pub,
		IngestTracker:     tracker,
	}

	tracker.Create("test-reg-1")

	ref := bus.IngestRef{
		JobID:    "test-reg-1",
		LogIndex: 0,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer: "https://issuer.example.com",
			Sub:    "admin@complytime.dev",
		},
		Timestamp: time.Now(),
	}

	handler := IngestWorker(ctx, stores, pub, tracker, reader)

	mockMsg := &fakeJSMsg{}
	handler(ctx, ref, mockMsg)

	assert.True(t, mockMsg.acked, "message should be acked")
	assert.Len(t, pub.targetCalls, 1)
	assert.Equal(t, "tgt-smoke", pub.targetCalls[0])

	// Verify NATS KV was updated
	target, err := targetStore.GetLatestTarget(ctx, "tgt-smoke", time.Now())
	require.NoError(t, err)
	require.NotNil(t, target)
	assert.Equal(t, "Smoke Test Target", target.TargetName)

	pubs, err := pubTrust.GetTrustedPublishers(ctx, "tgt-smoke")
	require.NoError(t, err)
	assert.Len(t, pubs, 1)
	assert.Equal(t, "repo:org/repo", pubs[0].SubPattern)
}

func TestIngestWorker_MissingEntry_Naks(t *testing.T) {
	reader := &staticReader{data: map[uint64][]byte{}}
	pub := &recordingPublisher{}
	tracker := NewIngestTracker()

	js := startIngestTestNATS(t)
	ctx := context.Background()

	targetStore, err := bus.NewTargetStoreKV(ctx, js)
	require.NoError(t, err)
	pubTrust, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	stores := Stores{
		Targets:           targetStore,
		TrustedPublishers: pubTrust,
		EventPublisher:    pub,
		IngestTracker:     tracker,
	}

	tracker.Create("test-missing")

	ref := bus.IngestRef{JobID: "test-missing", LogIndex: 99}

	handler := IngestWorker(ctx, stores, pub, tracker, reader)

	mockMsg := &fakeJSMsg{}
	handler(ctx, ref, mockMsg)

	assert.True(t, mockMsg.termed, "message should be termed for missing entry")

	status := tracker.Get("test-missing")
	require.NotNil(t, status)
	assert.Equal(t, "failed", status.Status)
}

// fakeJSMsg implements just enough of jetstream.Msg for testing outcomes.
type fakeJSMsg struct {
	acked  bool
	naked  bool
	termed bool
}

func (m *fakeJSMsg) Ack() error                                { m.acked = true; return nil }
func (m *fakeJSMsg) Nak() error                                { m.naked = true; return nil }
func (m *fakeJSMsg) NakWithDelay(_ time.Duration) error        { m.naked = true; return nil }
func (m *fakeJSMsg) Term() error                               { m.termed = true; return nil }
func (m *fakeJSMsg) TermWithReason(_ string) error             { m.termed = true; return nil }
func (m *fakeJSMsg) InProgress() error                         { return nil }
func (m *fakeJSMsg) Metadata() (*jetstream.MsgMetadata, error) { return nil, nil }
func (m *fakeJSMsg) Headers() nats.Header                      { return nil }
func (m *fakeJSMsg) Data() []byte                              { return nil }
func (m *fakeJSMsg) Subject() string                           { return "" }
func (m *fakeJSMsg) Reply() string                             { return "" }
func (m *fakeJSMsg) DoubleAck(_ context.Context) error         { return nil }

// Satisfy the full interface — these aren't used in tests.
var _ jetstream.Msg = (*fakeJSMsg)(nil)
