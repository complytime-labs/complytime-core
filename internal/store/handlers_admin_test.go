// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// ── Additional mocks for admin handler tests ──────────────────────────────

type mockTargetStore struct {
	insertErr      error
	insertedTarget *requirements.TargetRow
}

func (m *mockTargetStore) InsertTarget(_ context.Context, row requirements.TargetRow) error {
	m.insertedTarget = &row
	return m.insertErr
}

func (m *mockTargetStore) GetLatestTarget(_ context.Context, _ string, _ time.Time) (*requirements.TargetRow, error) {
	return nil, nil
}

func (m *mockTargetStore) ListTargets(_ context.Context) ([]requirements.TargetRow, error) {
	return nil, nil
}

type mockTrustStoreWithCapture struct {
	mockTrustStore
	insertedPublishers []requirements.TrustedPublisherRow
}

func (m *mockTrustStoreWithCapture) InsertTrustedPublishers(_ context.Context, rows []requirements.TrustedPublisherRow) error {
	m.insertedPublishers = rows
	return nil
}

type mockEventPublisher struct{}

func (m *mockEventPublisher) PublishEvidence(_, _, _ string, _ int, _ uint64) {}
func (m *mockEventPublisher) PublishDraftAuditLog(_, _, _, _ string)          {}
func (m *mockEventPublisher) PublishPolicyNew(_ uint64, _, _ string)          {}
func (m *mockEventPublisher) PublishTargetRegistered(_ uint64, _, _ string)   {}

// ── Admin handler tests ────────────────────────────────────────────────────

func TestAdminRegisterTargetHandler_Success(t *testing.T) {
	var tesseraCapture []byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		tesseraCapture = data
		return 42, nil
	}}
	targets := &mockTargetStore{}
	trustedPubs := &mockTrustStore{trusted: true}
	authorizer := &mockAuthorizer{allowed: true}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:acme/infra",
	}}
	publisher := &mockEventPublisher{}

	handler := AdminRegisterTargetHandler(appender, verifier, targets, trustedPubs, authorizer, publisher)

	body := []byte(`metadata:
  type: TargetRegistration
  id: reg-001
  date: "2026-06-29T20:00:00Z"
target:
  id: prod-cluster
  name: Production Cluster
  type: kubernetes
  trusted-publishers:
    - issuer: https://token.actions.githubusercontent.com
      sub_pattern: "repo:acme/*"
dimensions:
  technologies: [kubernetes]
`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	assert.NotEmpty(t, tesseraCapture)
}

func TestAdminRegisterTargetHandler_Unauthorized(t *testing.T) {
	authorizer := &mockAuthorizer{allowed: false}
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}

	handler := AdminRegisterTargetHandler(nil, verifier, nil, nil, authorizer, nil)

	body := []byte("metadata:\n  type: TargetRegistration\ntarget:\n  id: tgt-1\n  name: T\n  type: k8s\n")
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdminRegisterTargetHandler_MissingAuth(t *testing.T) {
	handler := AdminRegisterTargetHandler(nil, nil, nil, nil, nil, nil)

	body := []byte("metadata:\n  type: TargetRegistration\ntarget:\n  id: tgt-1\n  name: T\n  type: k8s\n")
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminRegisterTargetHandler_InvalidBody(t *testing.T) {
	verifier := &mockVerifier{claims: &auth.JWTClaims{Sub: "s", Iss: "i"}}
	authorizer := &mockAuthorizer{allowed: true}

	handler := AdminRegisterTargetHandler(nil, verifier, nil, nil, authorizer, nil)

	body := []byte("not valid yaml {[")
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminRegisterTargetHandler_TrustedPublishersWritten(t *testing.T) {
	trustedPubs := &mockTrustStoreWithCapture{mockTrustStore: mockTrustStore{trusted: true}}

	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		return 100, nil
	}}
	targets := &mockTargetStore{}
	authorizer := &mockAuthorizer{allowed: true}
	verifier := &mockVerifier{claims: &auth.JWTClaims{
		Iss: "https://issuer",
		Sub: "admin-user",
	}}
	publisher := &mockEventPublisher{}

	handler := AdminRegisterTargetHandler(appender, verifier, targets, trustedPubs, authorizer, publisher)

	body := []byte(`metadata:
  type: TargetRegistration
  id: reg-002
  date: "2026-06-29T20:00:00Z"
target:
  id: prod-cluster
  name: Production Cluster
  type: kubernetes
  trusted-publishers:
    - issuer: https://token.actions.githubusercontent.com
      sub_pattern: "repo:acme/*"
`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	require.Len(t, trustedPubs.insertedPublishers, 1)
	assert.Equal(t, "prod-cluster", trustedPubs.insertedPublishers[0].TargetID)
	assert.Equal(t, "https://token.actions.githubusercontent.com", trustedPubs.insertedPublishers[0].Issuer)
	assert.Equal(t, "repo:acme/*", trustedPubs.insertedPublishers[0].SubPattern)
}
