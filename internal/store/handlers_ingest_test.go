// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// ── Test mocks ─────────────────────────────────────────────────────────────

type mockAppender struct {
	addFn func(ctx context.Context, data []byte) (uint64, error)
}

func (m *mockAppender) Add(ctx context.Context, data []byte) (uint64, error) {
	return m.addFn(ctx, data)
}

type mockVerifier struct {
	claims *auth.JWTClaims
	err    error
}

func (m *mockVerifier) Verify(_ context.Context, _ string) (*auth.JWTClaims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

type mockTrustStore struct {
	trusted bool
}

func (m *mockTrustStore) GetTrustedPublishers(_ context.Context, _ string) ([]requirements.TrustedPublisherRow, error) {
	if m.trusted {
		return []requirements.TrustedPublisherRow{
			{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/*"},
		}, nil
	}
	return nil, nil
}

func (m *mockTrustStore) InsertTrustedPublishers(_ context.Context, _ []requirements.TrustedPublisherRow) error {
	return nil
}

func (m *mockTrustStore) RemoveTrustedPublishers(_ context.Context, _ string, _ []requirements.TrustedPublisherKey, _ uint64) error {
	return nil
}

type mockAuthorizer struct {
	allowed bool
}

func (m *mockAuthorizer) IsAuthorized(_ cedar.EntityUID, _ map[string]cedar.Value, _ cedar.EntityUID, _ cedar.EntityUID, _ map[string]cedar.Value) (bool, error) {
	return m.allowed, nil
}

type mockIngestPublisher struct{}

func (m *mockIngestPublisher) PublishIngest(_ context.Context, _ bus.IngestRef) error { return nil }

// ── Handler tests ──────────────────────────────────────────────────────────

func TestIngestAsyncHandler_YAMLReceiptWrap(t *testing.T) {
	var captured []byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		captured = data
		return 1, nil
	}}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/app",
	}}
	trustStore := &mockTrustStore{trusted: true}
	authorizer := &mockAuthorizer{allowed: true}
	tracker := NewIngestTracker()
	publisher := &mockIngestPublisher{}

	handler := IngestAsyncHandler(publisher, tracker, appender, verifier, trustStore, authorizer)

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-1\n")
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/yaml")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)
	require.NotNil(t, captured, "appender should have received data")
	assert.True(t, receipt.IsReceipt(captured), "Tessera entry should be a receipt, got: %s", string(captured))
}

func TestIngestAsyncHandler_JSONReceiptWrap(t *testing.T) {
	var captured []byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		captured = data
		return 2, nil
	}}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/app",
	}}
	trustStore := &mockTrustStore{trusted: true}
	authorizer := &mockAuthorizer{allowed: true}
	tracker := NewIngestTracker()
	publisher := &mockIngestPublisher{}

	handler := IngestAsyncHandler(publisher, tracker, appender, verifier, trustStore, authorizer)

	body := []byte(`{"metadata":{"type":"EvaluationLog"},"target":{"id":"tgt-2"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)
	require.NotNil(t, captured)
	assert.True(t, receipt.IsReceipt(captured), "Tessera entry should be a receipt")
}

func TestIngestAsyncHandler_DSSEPassThrough(t *testing.T) {
	// DSSE payload: {"target":{"id":"tgt-1"}} base64-encoded
	dsseBody := []byte(`{"payload":"eyJ0YXJnZXQiOnsiaWQiOiJ0Z3QtMSJ9fQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"abc123"}]}`)
	var captured []byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		captured = data
		return 3, nil
	}}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/app",
	}}
	trustStore := &mockTrustStore{trusted: true}
	authorizer := &mockAuthorizer{allowed: true}
	tracker := NewIngestTracker()
	publisher := &mockIngestPublisher{}

	handler := IngestAsyncHandler(publisher, tracker, appender, verifier, trustStore, authorizer)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(dsseBody))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/vnd.dsse+json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)
	require.NotNil(t, captured)
	assert.False(t, receipt.IsReceipt(captured), "DSSE should be stored as-is, not wrapped in a receipt")
	assert.Equal(t, dsseBody, captured)
}

func TestIngestAsyncHandler_SizeLimit(t *testing.T) {
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}
	tracker := NewIngestTracker()

	handler := IngestAsyncHandler(nil, tracker, nil, verifier, nil, nil)

	bigBody := make([]byte, 256*1024+1)
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(bigBody))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestIngestAsyncHandler_RejectsTargetRegistration(t *testing.T) {
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}
	tracker := NewIngestTracker()

	handler := IngestAsyncHandler(nil, tracker, nil, verifier, nil, nil)

	body := []byte("metadata:\n  type: TargetRegistration\ntarget:\n  id: tgt-1\n")
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "target registration must use POST /api/admin/targets")
}

func TestIngestAsyncHandler_MissingTargetID(t *testing.T) {
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}
	tracker := NewIngestTracker()

	handler := IngestAsyncHandler(nil, tracker, nil, verifier, nil, nil)

	body := []byte("metadata:\n  type: EvaluationLog\n")
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "artifact missing target.id")
}

func TestIngestAsyncHandler_MissingAuth(t *testing.T) {
	handler := IngestAsyncHandler(nil, NewIngestTracker(), nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader([]byte("test")))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIngestAsyncHandler_EmptyBody(t *testing.T) {
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}
	handler := IngestAsyncHandler(nil, NewIngestTracker(), nil, verifier, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader([]byte{}))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "request body is empty")
}

func TestIngestAsyncHandler_ReceiptContainsPublisherIdentity(t *testing.T) {
	var captured []byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		captured = data
		return 5, nil
	}}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/app",
	}}
	trustStore := &mockTrustStore{trusted: true}
	authorizer := &mockAuthorizer{allowed: true}
	tracker := NewIngestTracker()
	publisher := &mockIngestPublisher{}

	handler := IngestAsyncHandler(publisher, tracker, appender, verifier, trustStore, authorizer)

	body := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: tgt-check\n")
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/yaml")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusAccepted, w.Code)

	// Verify the receipt contains publisher identity
	pred, err := receipt.Unwrap(captured)
	require.NoError(t, err)
	assert.Equal(t, "https://token.actions.githubusercontent.com", pred.Publisher.Issuer)
	assert.Equal(t, "repo:acme/app", pred.Publisher.Subject)
	assert.Equal(t, "jwt-channel", pred.Publisher.Method)
	assert.Equal(t, "EvaluationLog", pred.ArtifactType)
}
