package graph

import (
	"encoding/json"
	"net/http"

	"github.com/cedar-policy/cedar-go"
	"github.com/go-chi/chi/v5"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
)

// APIHandler implements the ServerInterface for the graph API.
type APIHandler struct {
	writer *Writer
}

// NewHandler creates a new HTTP handler for the graph API.
// It returns a Chi router with all routes registered.
// If auth is non-nil, all routes except /healthz require JWT+Cedar authentication.
func NewHandler(writer *Writer, auth authn.Authenticator, policySet *cedar.PolicySet) http.Handler {
	h := &APIHandler{
		writer: writer,
	}

	r := chi.NewRouter()

	// If auth is provided, apply auth+authz middleware to all routes except /healthz
	if auth != nil {
		// Build the middleware chain once at init time
		authChain := func(next http.Handler) http.Handler {
			return authn.AuthMiddleware(auth)(authz.Middleware(policySet, nil)(next))
		}

		r.Use(func(next http.Handler) http.Handler {
			authed := authChain(next)
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// Skip auth for /healthz
				if req.URL.Path == "/healthz" {
					next.ServeHTTP(w, req)
					return
				}
				// Apply pre-built auth chain for all other routes
				authed.ServeHTTP(w, req)
			})
		})
	}

	// Register OpenAPI routes via generated code
	return HandlerFromMux(h, r)
}

// HealthCheck returns the service health status.
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ListSubjects returns all subjects with summary statistics.
func (h *APIHandler) ListSubjects(w http.ResponseWriter, r *http.Request) {
	subjects, err := h.writer.ListSubjects(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert from internal result type to API response type
	summaries := make([]SubjectSummary, len(subjects))
	for i, s := range subjects {
		summaries[i] = SubjectSummary{
			Id:             s.SubjectID,
			EvidenceCount:  s.EvidenceCount,
			PublisherCount: s.PublisherCount,
			ArtifactTypes:  s.ArtifactTypes,
		}
	}

	// Wrap in response object as per OpenAPI spec
	response := map[string]interface{}{
		"subjects": summaries,
	}

	respondJSON(w, http.StatusOK, response)
}

// GetSubject returns subject detail with per-artifact-type freshness.
func (h *APIHandler) GetSubject(w http.ResponseWriter, r *http.Request, id string) {
	summary, err := h.writer.SubjectSummary(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if summary == nil || summary.EvidenceCount == 0 {
		respondError(w, http.StatusNotFound, "subject not found")
		return
	}

	// Convert to API response type
	response := SubjectDetail{
		Id:             summary.SubjectID,
		EvidenceCount:  summary.EvidenceCount,
		PublisherCount: summary.PublisherCount,
		ArtifactTypes:  summary.ArtifactTypes,
	}

	respondJSON(w, http.StatusOK, response)
}

// GetThreatModel returns assembled threat model with provenance.
func (h *APIHandler) GetThreatModel(w http.ResponseWriter, r *http.Request, id string) {
	result, err := h.writer.ThreatModel(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if result == nil || (len(result.Capabilities) == 0 && len(result.Threats) == 0 && len(result.Controls) == 0 && len(result.Vectors) == 0) {
		respondError(w, http.StatusNotFound, "subject not found")
		return
	}

	// Convert to API response type
	response := ThreatModelResponse{
		SubjectId:    result.SubjectID,
		Capabilities: result.Capabilities,
		Threats:      result.Threats,
		Controls:     result.Controls,
		Vectors:      result.Vectors,
	}

	respondJSON(w, http.StatusOK, response)
}

// GetEvidence returns paginated evidence list with optional filtering.
func (h *APIHandler) GetEvidence(w http.ResponseWriter, r *http.Request, id string, params GetEvidenceParams) {
	// Apply default and max limit enforcement
	limit := 50 // default
	if params.Limit != nil {
		limit = *params.Limit
		if limit > 200 {
			limit = 200 // max cap
		}
		if limit < 1 {
			limit = 1
		}
	}

	// Build filter from query params
	filter := EvidenceFilter{
		ArtifactType: params.Type,
		Since:        params.Since,
		Before:       params.Before,
		Cursor:       params.Cursor,
		Limit:        &limit,
	}

	result, err := h.writer.Evidence(r.Context(), id, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert to API response type
	response := EvidenceListResponse{
		SubjectId:  result.SubjectID,
		Evidence:   result.Evidence,
		NextCursor: result.NextCursor,
	}

	respondJSON(w, http.StatusOK, response)
}

// GetCoverage returns coverage report for a catalog.
func (h *APIHandler) GetCoverage(w http.ResponseWriter, r *http.Request, id string, params GetCoverageParams) {
	result, err := h.writer.Coverage(r.Context(), id, params.Catalog)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if result == nil || result.Total == 0 {
		respondError(w, http.StatusNotFound, "subject not found")
		return
	}

	// Convert to API response type
	response := CoverageResponse{
		SubjectId:   result.SubjectID,
		Catalog:     result.Catalog,
		CatalogType: result.CatalogType,
		Covered:     result.Covered,
		Total:       result.Total,
		Controls:    result.Controls,
	}

	respondJSON(w, http.StatusOK, response)
}

// Helper functions

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If we can't encode the response, there's not much we can do
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, Error{Error: message})
}
