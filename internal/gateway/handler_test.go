package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authz"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func setupTestServer(t *testing.T) (*server.Server, *natsgo.Conn, jetstream.JetStream) {
	t.Helper()

	opts := &server.Options{
		JetStream: true,
		Port:      -1,
	}
	ns, err := server.NewServer(opts)
	require.NoError(t, err)

	go ns.Start()
	require.True(t, ns.ReadyForConnections(5e9))
	t.Cleanup(ns.Shutdown)

	nc, err := natsgo.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	return ns, nc, js
}

func setupTestHandler(t *testing.T, js jetstream.JetStream, nc *natsgo.Conn, lockerURL string) *GatewayHandler {
	t.Helper()

	trustStore, err := NewTrustStore(js)
	require.NoError(t, err)

	eventPublisher := NewEventPublisher(nc)

	handler := NewHandler(trustStore, js, eventPublisher, lockerURL, "test-secret")
	return handler
}

func TestIngestArtifact_ValidJSON(t *testing.T) {
	_, nc, js := setupTestServer(t)

	// Mock locker (not needed for async ingest, but handler requires URL)
	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	// Subscribe to ingested events (synchronous subscription)
	sub, err := nc.SubscribeSync("core.evidence.ingested.>")
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()
	require.NoError(t, sub.AutoUnsubscribe(1))

	// Create a test artifact
	artifact := map[string]interface{}{
		"target": map[string]interface{}{
			"id": "proj-1",
		},
		"type": "test-artifact",
		"data": "example data",
	}
	body, err := json.Marshal(artifact)
	require.NoError(t, err)

	// Create request with publisher context and X-Subject-ID header
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Subject-ID", "proj-1")
	ctx := authz.SetPublisherContext(req.Context(), "https://token.actions.githubusercontent.com", "repo:org/repo:ref:refs/heads/main")
	req = req.WithContext(ctx)

	// Execute request
	w := httptest.NewRecorder()
	handler.IngestArtifact(w, req)

	// Assertions
	assert.Equal(t, http.StatusAccepted, w.Code)

	var resp IngestResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.JobId)

	// Verify ingested event was published
	require.NoError(t, nc.Flush())
	msg, err := sub.NextMsg(natsgo.DefaultTimeout)
	require.NoError(t, err)
	assert.NotNil(t, msg)
}

func TestIngestArtifact_ValidDSSE(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	// Subscribe to ingested events (synchronous subscription)
	sub, err := nc.SubscribeSync("core.evidence.ingested.>")
	require.NoError(t, err)
	defer func() { _ = sub.Unsubscribe() }()
	require.NoError(t, sub.AutoUnsubscribe(1))

	// Create a mock DSSE envelope
	dsseEnvelope := map[string]interface{}{
		"payload":     "eyJ0ZXN0IjogInZhbHVlIn0=",
		"payloadType": "application/vnd.in-toto+json",
		"signatures": []map[string]interface{}{
			{
				"keyid": "test-key",
				"sig":   "test-signature",
			},
		},
	}
	body, err := json.Marshal(dsseEnvelope)
	require.NoError(t, err)

	// Create request with DSSE content type and X-Subject-ID header
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.dsse+json")
	req.Header.Set("X-Subject-ID", "proj-1")
	ctx := authz.SetPublisherContext(req.Context(), "https://token.actions.githubusercontent.com", "repo:org/repo:ref:refs/heads/main")
	req = req.WithContext(ctx)

	// Execute request
	w := httptest.NewRecorder()
	handler.IngestArtifact(w, req)

	// Assertions
	assert.Equal(t, http.StatusAccepted, w.Code)

	var resp IngestResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.JobId)

	// Verify ingested event was published
	require.NoError(t, nc.Flush())
	msg, err := sub.NextMsg(natsgo.DefaultTimeout)
	require.NoError(t, err)
	assert.NotNil(t, msg)
}

func TestIngestArtifact_MissingBody(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	// Create request with empty body
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Subject-ID", "proj-1")
	ctx := authz.SetPublisherContext(req.Context(), "https://token.actions.githubusercontent.com", "repo:org/repo:ref:refs/heads/main")
	req = req.WithContext(ctx)

	// Execute request
	w := httptest.NewRecorder()
	handler.IngestArtifact(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegisterSubject_Valid(t *testing.T) {
	_, nc, js := setupTestServer(t)

	// Mock locker
	var ledgerCreated, sealCalled bool
	mockLocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/ledgers" {
			ledgerCreated = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectId": "proj-1",
			})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/ledgers/proj-1/seal" {
			sealCalled = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"index":  int64(0),
				"digest": "test-digest",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer mockLocker.Close()

	handler := setupTestHandler(t, js, nc, mockLocker.URL)

	// Create registration request
	regReq := SubjectRegistrationRequest{
		SubjectId: "proj-1",
		TrustedPublishers: []TrustedPublisher{
			{
				Issuer: "https://token.actions.githubusercontent.com",
				Sub:    "repo:org/repo:ref:refs/heads/main",
			},
		},
	}
	body, err := json.Marshal(regReq)
	require.NoError(t, err)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/admin/subjects", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	w := httptest.NewRecorder()
	handler.RegisterSubject(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.True(t, ledgerCreated, "Ledger should be created")
	assert.True(t, sealCalled, "Seal should be called")

	var resp SubjectRegistrationResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "proj-1", resp.SubjectId)
}

func TestGetJobStatus_Pending(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	// Create a pending job
	jobID := uuid.New()
	handler.Jobs.Store(jobID.String(), &JobInfo{
		JobID:  jobID,
		Status: Pending,
	})

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/ingest/jobs/"+jobID.String(), nil)

	// Execute request
	w := httptest.NewRecorder()
	handler.GetJobStatus(w, req, types.UUID(jobID))

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var status JobStatus
	err := json.NewDecoder(w.Body).Decode(&status)
	require.NoError(t, err)
	assert.Equal(t, Pending, status.Status)
	assert.Equal(t, jobID, uuid.UUID(status.JobId))
}

func TestGetJobStatus_NotFound(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	jobID := uuid.New()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/ingest/jobs/"+jobID.String(), nil)

	// Execute request
	w := httptest.NewRecorder()
	handler.GetJobStatus(w, req, types.UUID(jobID))

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHealthCheck(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc, "http://locker.example.com")

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	// Execute request
	w := httptest.NewRecorder()
	handler.HealthCheck(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var health map[string]string
	err := json.NewDecoder(w.Body).Decode(&health)
	require.NoError(t, err)
	assert.Equal(t, "ok", health["status"])
}
