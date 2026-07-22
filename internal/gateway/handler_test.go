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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/trust"
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

func setupTestHandler(t *testing.T, js jetstream.JetStream, nc *natsgo.Conn) *GatewayHandler {
	t.Helper()

	trustStore, err := trust.NewTrustStore(js)
	require.NoError(t, err)

	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-test")

	// Load Gemara schemas
	schemas, err := NewSchemaRegistry()
	require.NoError(t, err)

	handler := NewHandler(trustStore, js, eventPublisher, schemas)
	return handler
}

func TestIngestArtifact_ValidJSON(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc)

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

	handler := setupTestHandler(t, js, nc)

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

	handler := setupTestHandler(t, js, nc)

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

func TestHealthCheck(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc)

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

func TestIngestArtifact_InvalidGemaraSchema(t *testing.T) {
	_, nc, js := setupTestServer(t)

	handler := setupTestHandler(t, js, nc)

	// Create an invalid EvaluationLog - missing required fields: evaluations, result, target
	invalidArtifact := map[string]interface{}{
		"metadata": map[string]interface{}{
			"type":           "EvaluationLog",
			"id":             "test-eval-1",
			"description":    "Invalid evaluation log for testing",
			"gemara-version": "1.0.0",
			"author": map[string]interface{}{
				"id":   "test-author",
				"name": "Test Author",
				"type": "Software",
			},
		},
		// Missing required fields: evaluations, result, target
	}
	body, err := json.Marshal(invalidArtifact)
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
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var errResp map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&errResp)
	require.NoError(t, err)

	// Verify error response structure
	assert.Contains(t, errResp, "error", "Response should contain 'error' field")
	assert.Contains(t, errResp, "artifactType", "Response should contain 'artifactType' field")
	assert.Contains(t, errResp, "details", "Response should contain 'details' field")

	// Verify artifact type
	assert.Equal(t, "EvaluationLog", errResp["artifactType"])

	// Verify details is an array
	details, ok := errResp["details"].([]interface{})
	require.True(t, ok, "details should be an array")
	assert.NotEmpty(t, details, "details should contain validation errors")
}
