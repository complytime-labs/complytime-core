// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/receipt"
)

// TestIngestPipeline_EndToEnd exercises the full flow:
//
//  1. Register a target with trusted publishers via POST /api/admin/targets
//  2. Submit evidence for that target via POST /api/ingest
//  3. Worker reads the receipt from Tessera, unwraps it, detects the artifact type
//  4. Worker publishes an evidence event on NATS
//  5. A test subscriber receives the event and verifies its contents
func TestIngestPipeline_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// ── Infrastructure: embedded NATS + in-memory Tessera ──────────────

	ns := startTestNATSServer(t)
	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	js, err := jetstream.New(nc)
	require.NoError(t, err)

	targetStore, err := bus.NewTargetStoreKV(ctx, js)
	require.NoError(t, err)
	pubTrust, err := bus.NewPublisherTrustKV(ctx, js)
	require.NoError(t, err)

	nbus, err := bus.Connect(ns.ClientURL(), "")
	require.NoError(t, err)
	require.NoError(t, nbus.EnsureIngestStream(ctx, bus.IngestStreamConfig{}))

	tessera := &inMemoryTessera{}
	tracker := NewIngestTracker()

	// ── Step 0: Subscribe for events before anything happens ──────────

	var (
		targetEvent   bus.TargetRegisteredEvent
		evidenceEvent bus.EvidenceEvent
		rawCEMsg      []byte
		mu            sync.Mutex
		targetCh      = make(chan struct{}, 1)
		evidenceCh    = make(chan struct{}, 1)
	)

	_, err = nc.Subscribe("core.target.registered", func(msg *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		parsed, parseErr := bus.ParseCloudEventData[bus.TargetRegisteredEvent](msg.Data)
		if parseErr != nil {
			t.Logf("parse target event error: %v", parseErr)
			return
		}
		targetEvent = parsed
		select {
		case targetCh <- struct{}{}:
		default:
		}
	})
	require.NoError(t, err)

	_, err = nc.Subscribe("core.evidence.>", func(msg *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if rawCEMsg == nil {
			rawCEMsg = append([]byte{}, msg.Data...)
		}
		parsed, parseErr := bus.ParseCloudEventData[bus.EvidenceEvent](msg.Data)
		if parseErr != nil {
			t.Logf("parse evidence event error: %v", parseErr)
			return
		}
		evidenceEvent = parsed
		select {
		case evidenceCh <- struct{}{}:
		default:
		}
	})
	require.NoError(t, err)

	// ── Step 1: Register target ───────────────────────────────────────

	targetYAML := []byte(`metadata:
  type: TargetRegistration
  id: demo-reg-001
  date: "2026-06-29T20:00:00Z"
target:
  id: demo-app
  name: Demo Application
  type: web-service
  trusted-publishers:
    - issuer: https://token.actions.githubusercontent.com
      sub_pattern: "repo:acme/scanner:*"
dimensions:
  technologies: [go]
`)

	adminHandler := AdminRegisterTargetHandler(
		tessera, stubVerifier(), targetStore, pubTrust, &mockAuthorizer{allowed: true}, nbus,
	)

	adminReq := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(targetYAML))
	adminReq.Header.Set("Authorization", "Bearer admin-token")
	adminW := httptest.NewRecorder()
	adminHandler.ServeHTTP(adminW, adminReq)

	require.Equal(t, http.StatusCreated, adminW.Code, "admin register should succeed: %s", adminW.Body.String())

	var adminResp map[string]any
	require.NoError(t, json.Unmarshal(adminW.Body.Bytes(), &adminResp))
	assert.Equal(t, "demo-app", adminResp["target_id"])
	t.Logf("Target registered: %s (log_index=%.0f)", adminResp["target_id"], adminResp["log_index"])

	// Wait for target registered event
	select {
	case <-targetCh:
		mu.Lock()
		assert.Equal(t, "demo-app", targetEvent.TargetID)
		assert.Equal(t, "repo:acme/scanner:main", targetEvent.RegisteredBy)
		t.Logf("Event received: core.target.registered → target_id=%s", targetEvent.TargetID)
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for core.target.registered event")
	}

	// ── Step 2: Submit evidence via ingest handler ─────────────────────

	evidenceYAML := []byte(`metadata:
  type: EvaluationLog
  id: eval-demo-001
  version: 1.0.0
  author:
    name: compliance-scanner
    type: Software
    version: 2.0.0
  date: "2026-06-29T21:00:00Z"
  mapping-references:
    - id: nist-800-53
      title: NIST 800-53
      version: "rev5"
target:
  id: demo-app
  name: Demo Application
  type: web-service
evaluations:
  - control:
      entry-id: AC-1
      reference-id: nist-800-53
    assessment-logs:
      - result: Passed
        start: "2026-06-29T21:00:00Z"
        requirement:
          entry-id: AC-1.1
`)

	ingestHandler := IngestAsyncHandler(
		nbus, tracker, tessera,
		stubVerifier(), pubTrust, &mockAuthorizer{allowed: true},
	)

	ingestReq := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(evidenceYAML))
	ingestReq.Header.Set("Authorization", "Bearer pipeline-token")
	ingestReq.Header.Set("Content-Type", "application/yaml")
	ingestW := httptest.NewRecorder()
	ingestHandler.ServeHTTP(ingestW, ingestReq)

	require.Equal(t, http.StatusAccepted, ingestW.Code, "ingest should succeed: %s", ingestW.Body.String())

	var ingestResp map[string]any
	require.NoError(t, json.Unmarshal(ingestW.Body.Bytes(), &ingestResp))
	logIndex := uint64(ingestResp["log_index"].(float64))
	t.Logf("Evidence ingested: job_id=%s log_index=%d", ingestResp["job_id"], logIndex)

	// Verify the Tessera entry is a receipt
	raw, err := tessera.Read(ctx, logIndex)
	require.NoError(t, err)
	assert.True(t, receipt.IsReceipt(raw), "Tessera entry should be a receipt")

	pred, err := receipt.Unwrap(raw)
	require.NoError(t, err)
	assert.Equal(t, "EvaluationLog", pred.ArtifactType)
	assert.Equal(t, "Software", pred.AuthorType)
	assert.Equal(t, "repo:acme/scanner:main", pred.Publisher.Subject)
	assert.Equal(t, "jwt-channel", pred.Publisher.Method)
	t.Logf("Receipt verified: artifactType=%s authorType=%s publisher=%s",
		pred.ArtifactType, pred.AuthorType, pred.Publisher.Subject)

	// ── Step 3: Worker processes the receipt ───────────────────────────

	stores := Stores{
		Targets:           targetStore,
		TrustedPublishers: pubTrust,
		EventPublisher:    nbus,
		IngestTracker:     tracker,
	}

	jobID := ingestResp["job_id"].(string)
	ref := bus.IngestRef{
		JobID:    jobID,
		LogIndex: logIndex,
		PublisherIdentity: bus.PublisherIdentity{
			Issuer:   "https://token.actions.githubusercontent.com",
			Sub:      "repo:acme/scanner:main",
			Type:     "pipeline",
			Verified: true,
		},
		Timestamp: time.Now().UTC(),
	}

	workerHandler := IngestWorker(ctx, stores, nbus, tracker, tessera)
	mockMsg := &fakeJSMsg{}
	workerHandler(ctx, ref, mockMsg)

	assert.True(t, mockMsg.acked, "worker should ack the message")

	status := tracker.Get(jobID)
	require.NotNil(t, status)
	assert.Equal(t, "completed", status.Status)
	t.Logf("Worker completed: job_id=%s status=%s", jobID, status.Status)

	// ── Step 4: Verify evidence event was emitted ─────────────────────

	select {
	case <-evidenceCh:
		mu.Lock()
		assert.Equal(t, "nist-800-53", evidenceEvent.PolicyID)
		assert.Equal(t, "demo-app", evidenceEvent.TargetID)
		assert.Equal(t, "EvaluationLog", evidenceEvent.ArtifactType)
		assert.Equal(t, 1, evidenceEvent.RecordCount)
		t.Logf("Event received: core.evidence.%s → target=%s artifact_type=%s record_count=%d",
			evidenceEvent.PolicyID, evidenceEvent.TargetID, evidenceEvent.ArtifactType, evidenceEvent.RecordCount)

		// Verify the raw message is a valid CloudEvents envelope
		assert.NotNil(t, rawCEMsg, "should have captured raw CloudEvents message")
		rawStr := string(rawCEMsg)
		assert.Contains(t, rawStr, `"specversion":"1.0"`)
		assert.Contains(t, rawStr, `"type":"dev.complytime.evidence.ingested"`)
		assert.Contains(t, rawStr, `"subject":"demo-app"`)
		t.Logf("CloudEvents envelope verified: %s", rawStr)
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for core.evidence.* event")
	}

	t.Log("─── Pipeline complete: target registered → evidence ingested → receipt verified → event emitted ───")
}

// ── Test helpers ──────────────────────────────────────────────────────────

func startTestNATSServer(t *testing.T) *server.Server {
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

// inMemoryTessera is an in-memory transparency log for testing.
type inMemoryTessera struct {
	mu      sync.Mutex
	entries [][]byte
}

func (t *inMemoryTessera) Add(_ context.Context, data []byte) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := uint64(len(t.entries))
	t.entries = append(t.entries, append([]byte{}, data...))
	return idx, nil
}

func (t *inMemoryTessera) Read(_ context.Context, index uint64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if index >= uint64(len(t.entries)) {
		return nil, fmt.Errorf("index %d not found", index)
	}
	return t.entries[index], nil
}

func stubVerifier() JWTVerifier {
	return &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/scanner:main",
	}}
}
