package locker

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/complytime-labs/complytime-core/internal/subjects"
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

	r.Use(otelhttp.NewMiddleware("complytime-locker"))

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

// CreateLedger creates a new ledger for a subject.
func (h *APIHandler) CreateLedger(w http.ResponseWriter, r *http.Request) {
	initTelemetry()

	ctx, span := lockerTracer.Start(r.Context(), "locker.ledger.create")
	defer span.End()

	var req CreateLedgerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SubjectId == "" {
		respondError(w, http.StatusBadRequest, "subjectId is required")
		return
	}

	if err := subjects.ValidateSubjectID(req.SubjectId); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	ledger, err := h.locker.CreateLedger(ctx, req.SubjectId)
	if err != nil {
		if errors.Is(err, ErrLedgerExists) {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	span.SetAttributes(attribute.String("subjectId", req.SubjectId))

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
	initTelemetry()

	ctx, span := lockerTracer.Start(r.Context(), "locker.seal")
	defer span.End()

	start := time.Now()

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

	idx, err := ledger.Seal(ctx, receiptData)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	digest := SHA256Hex(receiptData)

	// Record metrics and span attributes
	span.SetAttributes(
		attribute.String("subjectId", subjectID),
		attribute.Int64("logIndex", int64(idx)),
		attribute.String("contentDigest", digest),
	)
	sealTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("subjectId", subjectID)))
	sealDuration.Record(ctx, time.Since(start).Seconds())

	resp := SealResponse{
		Index:  int64(idx), //nolint:gosec // G115: log indices won't exceed int64 max
		Digest: digest,
	}
	respondJSON(w, http.StatusCreated, resp)
}

// FetchReceipt retrieves a sealed receipt by index.
func (h *APIHandler) FetchReceipt(w http.ResponseWriter, r *http.Request, subjectID string, index int64) {
	initTelemetry()

	ctx, span := lockerTracer.Start(r.Context(), "locker.fetch")
	defer span.End()

	start := time.Now()

	ledger, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "ledger not found")
		return
	}

	if index < 0 {
		respondError(w, http.StatusBadRequest, "index must be non-negative")
		return
	}

	receipt, err := ledger.Fetch(ctx, uint64(index))
	if err != nil {
		if errors.Is(err, ErrIndexOutOfRange) {
			respondError(w, http.StatusNotFound, "receipt not found")
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Record metrics and span attributes
	span.SetAttributes(
		attribute.String("subjectId", subjectID),
		attribute.Int64("index", index),
	)
	fetchTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("subjectId", subjectID)))
	fetchDuration.Record(ctx, time.Since(start).Seconds())

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
	initTelemetry()

	ctx, span := lockerTracer.Start(r.Context(), "locker.verify")
	defer span.End()

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

	// Record metrics and span attributes
	foundStr := "false"
	if found {
		foundStr = "true"
	}
	span.SetAttributes(
		attribute.String("subjectId", subjectID),
		attribute.Bool("found", found),
	)
	verifyTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("found", foundStr)))

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

// RegisterSubject handles POST /admin/subjects
func (h *APIHandler) RegisterSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req SubjectRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.SubjectId == "" {
		respondError(w, http.StatusBadRequest, "missing subjectId")
		return
	}
	if err := subjects.ValidateSubjectID(req.SubjectId); err != nil {
		respondError(w, http.StatusBadRequest, "invalid subjectId")
		return
	}
	if len(req.TrustedPublishers) == 0 {
		respondError(w, http.StatusBadRequest, "at least one trusted publisher required")
		return
	}

	// Create ledger (direct call, no HTTP)
	ledger, err := h.locker.CreateLedger(ctx, req.SubjectId)
	if err != nil {
		if errors.Is(err, ErrLedgerExists) {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Wrap registration as a receipt
	regData := map[string]interface{}{
		"subjectId":         req.SubjectId,
		"trustedPublishers": req.TrustedPublishers,
	}
	regBytes, err := json.Marshal(regData)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to marshal registration")
		return
	}

	// Use authenticated caller as the one performing registration
	issuer, sub := authz.GetPublisher(ctx)
	publisher := receipt.Publisher{
		Issuer: issuer,
		Sub:    sub,
	}

	receiptBytes, err := receipt.Wrap(regBytes, publisher, req.SubjectId, "subject-registration")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to wrap registration receipt")
		return
	}

	// Seal registration receipt (direct call)
	_, err = ledger.Seal(ctx, receiptBytes)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to seal registration")
		return
	}

	// Update trust store
	trustEntries := make([]trust.TrustEntry, len(req.TrustedPublishers))
	for i, tp := range req.TrustedPublishers {
		trustEntries[i] = trust.TrustEntry(tp)
	}

	if err := h.trustStore.SetPublisherTrust(ctx, req.SubjectId, trustEntries); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update trust store")
		return
	}

	// Register subject in subject registry
	if err := h.trustStore.RegisterSubject(ctx, req.SubjectId); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to register subject")
		return
	}

	// Publish CloudEvent
	if err := h.events.PublishSubjectRegistered(ctx, req.SubjectId); err != nil {
		// Log error but don't fail the request
		slog.Warn("failed to publish subject.registered event", "error", err, "subjectId", SanitizeLogValue(req.SubjectId))
	}

	// Return 201
	respondJSON(w, http.StatusCreated, SubjectRegistrationResponse{
		SubjectId: req.SubjectId,
	})
}

// ModifyTrust handles PUT /admin/subjects/{subjectId}/trust
func (h *APIHandler) ModifyTrust(w http.ResponseWriter, r *http.Request, subjectID string) {
	ctx := r.Context()

	// Parse request body
	var req ModifyTrustRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate subject ID
	if err := subjects.ValidateSubjectID(subjectID); err != nil {
		respondError(w, http.StatusBadRequest, "invalid subjectId")
		return
	}

	// Verify subject exists
	_, ok := h.locker.GetLedger(subjectID)
	if !ok {
		respondError(w, http.StatusNotFound, "subject not found")
		return
	}

	// Update trust store
	trustEntries := make([]trust.TrustEntry, len(req.TrustedPublishers))
	for i, tp := range req.TrustedPublishers {
		trustEntries[i] = trust.TrustEntry(tp)
	}

	if err := h.trustStore.SetPublisherTrust(ctx, subjectID, trustEntries); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update trust store")
		return
	}

	// Return 200
	respondJSON(w, http.StatusOK, ModifyTrustResponse{
		SubjectId: subjectID,
	})
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
