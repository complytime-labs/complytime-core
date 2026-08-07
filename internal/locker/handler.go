package locker

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cedar-policy/cedar-go"
	"github.com/go-chi/chi/v5"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

// APIHandler implements the ServerInterface for the locker API.
type APIHandler struct {
	locker     *Locker
	trustStore *trust.TrustStore
	events     *eventspkg.EventPublisher
}

// NewHandler creates a new HTTP handler for the locker API.
// It returns a Chi router with all routes registered.
// If auth is non-nil, all routes except /healthz require JWT+Cedar authentication.
func NewHandler(lk *Locker, auth authn.Authenticator, policySet *cedar.PolicySet, trustStore *trust.TrustStore, eventPublisher *eventspkg.EventPublisher) http.Handler {
	h := &APIHandler{
		locker:     lk,
		trustStore: trustStore,
		events:     eventPublisher,
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

	// Register tile server routes (checkpoint and tiles)
	registerTileRoutes(r, lk)

	// Register OpenAPI routes via generated code
	return HandlerFromMux(h, r)
}

// ListLedgers returns all active ledgers.
func (h *APIHandler) ListLedgers(w http.ResponseWriter, r *http.Request) {
	subjects := h.locker.Subjects()
	ledgers := make([]LedgerInfo, 0, len(subjects))

	for _, subjectID := range subjects {
		ledger, ok := h.locker.GetLedger(subjectID)
		if !ok {
			continue
		}
		ledgers = append(ledgers, LedgerInfo{
			SubjectId:   ledger.SubjectID(),
			VerifierKey: ledger.VerifierKey(),
		})
	}

	resp := LedgerList{Ledgers: ledgers}
	respondJSON(w, http.StatusOK, resp)
}

// GetLedger returns information about a specific ledger.
func (h *APIHandler) GetLedger(w http.ResponseWriter, r *http.Request, subjectID string) {
	ledger, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "ledger not found")
		return
	}

	resp := LedgerInfo{
		SubjectId:   ledger.SubjectID(),
		VerifierKey: ledger.VerifierKey(),
	}
	respondJSON(w, http.StatusOK, resp)
}

// FetchReceipt retrieves a sealed receipt by index.
func (h *APIHandler) FetchReceipt(w http.ResponseWriter, r *http.Request, subjectID string, index int64) {
	ledger, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "ledger not found")
		return
	}

	if index < 0 {
		respondError(w, http.StatusBadRequest, "index must be non-negative")
		return
	}

	receipt, err := ledger.Fetch(r.Context(), uint64(index))
	if err != nil {
		if errors.Is(err, ErrIndexOutOfRange) {
			respondError(w, http.StatusNotFound, "receipt not found")
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return raw binary data
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(receipt); err != nil {
		// Log the error but can't change response at this point
		return
	}
}

// VerifyReceipt checks if a receipt with the given digest exists.
func (h *APIHandler) VerifyReceipt(w http.ResponseWriter, r *http.Request, subjectID string, digest string) {
	ledger, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "ledger not found")
		return
	}

	if digest == "" {
		respondError(w, http.StatusBadRequest, "digest is required")
		return
	}

	idx, found := ledger.VerifyDigest(digest)

	resp := VerifyResponse{
		Found: found,
	}
	if found {
		idx64 := int64(idx) //nolint:gosec // G115: log indices won't exceed int64 max
		resp.Index = &idx64
	}

	respondJSON(w, http.StatusOK, resp)
}

// HealthCheck returns the service health status.
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
