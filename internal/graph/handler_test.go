//go:build integration

package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupHandler(t *testing.T) (http.Handler, *Writer) {
	t.Helper()
	driver := testDriver(t)
	clearGraph(t, driver)
	w := NewWriter(driver)
	handler := NewHandler(w, nil, nil)
	return handler, w
}

func TestHandler_Healthz(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandler_ListSubjects_Empty(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/subjects", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp []SubjectSummary
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp)
}

func TestHandler_ListSubjects_WithData(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "CapabilityCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))

	req := httptest.NewRequest("GET", "/api/subjects", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp []SubjectSummary
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Len(t, resp, 1)
	assert.Equal(t, "my-app-v1", resp[0].Id)
	assert.Equal(t, int64(1), resp[0].EvidenceCount)
}

func TestHandler_GetSubject(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "CapabilityCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp SubjectDetail
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-app-v1", resp.Id)
	assert.Equal(t, int64(1), resp.EvidenceCount)
}

func TestHandler_GetSubject_NotFound(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/subjects/nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandler_ThreatModel(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "CapabilityCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))
	require.NoError(t, w.UpsertEntity(ctx, EntityRecord{
		ID: "cap-1", Label: "Capability",
		Properties:       map[string]any{"title": "Login"},
		EvidenceLogIndex: 1,
	}))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1/threat-model", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ThreatModelResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-app-v1", resp.SubjectId)
	require.Len(t, resp.Capabilities, 1)
}

func TestHandler_ThreatModel_NotFound(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/subjects/nonexistent/threat-model", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandler_Evidence(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "CapabilityCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1/evidence", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp EvidenceListResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-app-v1", resp.SubjectId)
	require.Len(t, resp.Evidence, 1)
	assert.Equal(t, "sha256:abc", resp.Evidence[0].Digest)
}

func TestHandler_Evidence_WithFilters(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "CapabilityCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 2, Digest: "sha256:def", ArtifactType: "ThreatCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1/evidence?type=CapabilityCatalog", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp EvidenceListResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-app-v1", resp.SubjectId)
	require.Len(t, resp.Evidence, 1)
	assert.Equal(t, "CapabilityCatalog", resp.Evidence[0].ArtifactType)
}

func TestHandler_Coverage_RequiresCatalog(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1/coverage", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandler_Coverage(t *testing.T) {
	handler, w := setupHandler(t)

	ctx := context.Background()
	require.NoError(t, w.UpsertSubject(ctx, "my-app-v1"))
	require.NoError(t, w.UpsertPublisher(ctx, "https://idp", "arch"))
	require.NoError(t, w.UpsertEvidence(ctx, EvidenceRecord{
		LogIndex: 1, Digest: "sha256:abc", ArtifactType: "ControlCatalog",
		Status: "sealed", SubjectID: "my-app-v1",
		PublisherIssuer: "https://idp", PublisherSub: "arch",
		Sealed: time.Now(),
	}))
	require.NoError(t, w.UpsertEntity(ctx, EntityRecord{
		ID: "ctrl-1", Label: "Control",
		Properties: map[string]any{
			"title":     "Access Control",
			"catalogID": "gemara:///com.example/catalog@1.0.0",
		},
		EvidenceLogIndex: 1,
	}))

	req := httptest.NewRequest("GET", "/api/subjects/my-app-v1/coverage?catalog=gemara:///com.example/catalog@1.0.0", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp CoverageResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "my-app-v1", resp.SubjectId)
	assert.Equal(t, "gemara:///com.example/catalog@1.0.0", resp.Catalog)
}

func TestHandler_Coverage_NotFound(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/subjects/nonexistent/coverage?catalog=gemara:///com.example/catalog@1.0.0", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
