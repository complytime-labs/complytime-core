package locker

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// APIHandler implements the ServerInterface for the locker API.
type APIHandler struct {
	locker *Locker
}

// NewHandler creates a new HTTP handler for the locker API.
// It returns a Chi router with all routes registered.
// If secret is non-empty, all routes except /healthz require Bearer token authentication.
func NewHandler(lk *Locker, secret string) http.Handler {
	h := &APIHandler{locker: lk}

	r := chi.NewRouter()

	// If secret is provided, apply auth middleware to all routes except /healthz
	if secret != "" {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// Skip auth for /healthz
				if req.URL.Path == "/healthz" {
					next.ServeHTTP(w, req)
					return
				}
				// Apply shared secret middleware for all other routes
				SharedSecretMiddleware(secret)(next).ServeHTTP(w, req)
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

// CreateLedger creates a new ledger for a subject.
func (h *APIHandler) CreateLedger(w http.ResponseWriter, r *http.Request) {
	var req CreateLedgerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SubjectId == "" {
		respondError(w, http.StatusBadRequest, "subjectId is required")
		return
	}

	if err := ValidateSubjectID(req.SubjectId); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	ledger, err := h.locker.CreateLedger(r.Context(), req.SubjectId)
	if err != nil {
		if errors.Is(err, ErrLedgerExists) {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := LedgerInfo{
		SubjectId:   ledger.SubjectID(),
		VerifierKey: ledger.VerifierKey(),
	}
	respondJSON(w, http.StatusCreated, resp)
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

// SealReceipt seals a receipt in the ledger.
func (h *APIHandler) SealReceipt(w http.ResponseWriter, r *http.Request, subjectID string) {
	ledger, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "ledger not found")
		return
	}

	// Limit request body size to 4MB (matching NATS max message size)
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	// Read raw binary data from request body
	receiptData, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if len(receiptData) == 0 {
		respondError(w, http.StatusBadRequest, "receipt is required")
		return
	}

	idx, err := ledger.Seal(r.Context(), receiptData)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	digest := SHA256Hex(receiptData)
	resp := SealResponse{
		Index:  int64(idx), //nolint:gosec // G115: log indices won't exceed int64 max
		Digest: digest,
	}
	respondJSON(w, http.StatusCreated, resp)
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
