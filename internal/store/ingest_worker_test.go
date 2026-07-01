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
	"github.com/complytime-labs/complytime-core/internal/receipt"
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

func (p *recordingPublisher) PublishEvidence(policyID, _ string, _ string, _ int, _ uint64) {
	p.evidenceCalls = append(p.evidenceCalls, policyID)
}
func (p *recordingPublisher) PublishDraftAuditLog(_, _, _, _ string) {}
func (p *recordingPublisher) PublishPolicyNew(logIndex uint64, _, _ string) {
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

// TestIngestWorker_TargetRegistrationUpdatesKV removed — TargetRegistration
// handling moved to admin API (Task 7)

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

func TestUnwrapEntry_Receipt(t *testing.T) {
	content := []byte(`{"metadata":{"type":"EvaluationLog"},"target":{"id":"tgt-1"}}`)
	canonical, digest, err := receipt.Canonicalize(content)
	require.NoError(t, err)

	pub := receipt.Publisher{Issuer: "https://issuer.example.com", Subject: "repo:org/repo", Method: "jwt-channel"}
	wrapped, err := receipt.Wrap(canonical, digest, pub, "EvaluationLog", "Software", time.Now())
	require.NoError(t, err)

	unwrapped, identity, isDSSE, err := unwrapEntry(wrapped)
	require.NoError(t, err)
	assert.False(t, isDSSE)
	assert.JSONEq(t, string(canonical), string(unwrapped))
	assert.Equal(t, "https://issuer.example.com", identity.Issuer)
	assert.Equal(t, "repo:org/repo", identity.Sub)
	assert.True(t, identity.Verified)
	assert.Equal(t, "pipeline", identity.Type)
}

func TestUnwrapEntry_DSSE(t *testing.T) {
	// DSSE envelope with base64-encoded JSON payload
	payload := []byte(`{"type":"EvaluationLog"}`)
	encodedPayload := "eyJ0eXBlIjoiRXZhbHVhdGlvbkxvZyJ9"
	dsse := []byte(`{"payload":"` + encodedPayload + `","payloadType":"application/vnd.gemara+json","signatures":[{"sig":"abc"}]}`)

	content, identity, isDSSE, err := unwrapEntry(dsse)
	require.NoError(t, err)
	assert.True(t, isDSSE)
	assert.JSONEq(t, string(payload), string(content))
	assert.Empty(t, identity.Sub)
}

func TestUnwrapEntry_DSSE_RawURLEncoding(t *testing.T) {
	// DSSE with RawURL base64 encoding (no padding)
	payload := []byte(`{"type":"EvaluationLog"}`)
	encodedPayload := "eyJ0eXBlIjoiRXZhbHVhdGlvbkxvZyJ9" // Same for this case, but without padding if needed
	dsse := []byte(`{"payload":"` + encodedPayload + `","payloadType":"application/vnd.gemara+json","signatures":[{"sig":"abc"}]}`)

	content, identity, isDSSE, err := unwrapEntry(dsse)
	require.NoError(t, err)
	assert.True(t, isDSSE)
	assert.JSONEq(t, string(payload), string(content))
	assert.Empty(t, identity.Sub)
}

func TestUnwrapEntry_LegacyYAML(t *testing.T) {
	legacy := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-1\n")
	content, identity, isDSSE, err := unwrapEntry(legacy)
	require.NoError(t, err)
	assert.False(t, isDSSE)
	assert.Equal(t, legacy, content)
	assert.Empty(t, identity.Sub)
}

// TestHandleTargetRegistrationJS_* tests removed — TargetRegistration
// handling moved to admin API (Task 7)
