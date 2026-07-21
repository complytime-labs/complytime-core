package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oapi-codegen/runtime/types"

	"github.com/complytime-labs/complytime-core/events"
	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/complytime-labs/complytime-core/internal/locker"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

const (
	// MaxBodySize is the maximum allowed request body size (256 KiB).
	MaxBodySize = 256 * 1024

	// ContentTypeDSSE is the content type for DSSE envelopes.
	ContentTypeDSSE = "application/vnd.dsse+json"

	// HeaderSubjectID is the header used to pass subject ID for DSSE requests.
	HeaderSubjectID = "X-Subject-ID"
)

// GatewayHandler implements the ServerInterface for the gateway.
type GatewayHandler struct {
	trustStore     *TrustStore
	js             jetstream.JetStream
	eventPublisher *EventPublisher
	lockerURL      string
	lockerClient   *http.Client

	// In-memory job tracking (exported so worker can share it)
	Jobs sync.Map // map[string]*JobInfo
}

// JobInfo tracks the status of an ingest job.
type JobInfo struct {
	JobID     uuid.UUID
	Status    JobStatusStatus
	Digest    *string
	LogIndex  *int64
	SubjectID string
}

// IngestRef is the message structure published to JetStream for ingest work items.
type IngestRef struct {
	JobID                   string `json:"jobId"`
	SubjectID               string `json:"subjectId"`
	IsDSSE                  bool   `json:"isDSSE"`
	ContentDigest           string `json:"contentDigest"`
	ArtifactType            string `json:"artifactType"`
	ReceiptBytes            []byte `json:"receiptBytes,omitempty"`
	DSSEBytes               []byte `json:"dsseBytes,omitempty"`
	DSSEChannelReceiptBytes []byte `json:"dsseChannelReceiptBytes,omitempty"`
}

// NewHandler creates a new GatewayHandler with dependencies.
func NewHandler(
	trustStore *TrustStore,
	js jetstream.JetStream,
	eventPublisher *EventPublisher,
	lockerURL string,
	lockerClient *http.Client,
) *GatewayHandler {
	return &GatewayHandler{
		trustStore:     trustStore,
		js:             js,
		eventPublisher: eventPublisher,
		lockerURL:      lockerURL,
		lockerClient:   lockerClient,
	}
}

// IngestArtifact handles POST /api/ingest
func (h *GatewayHandler) IngestArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get publisher from context
	issuer, sub := authz.GetPublisher(ctx)
	if issuer == "" || sub == "" {
		http.Error(w, "Unauthorized: missing publisher identity", http.StatusUnauthorized)
		return
	}

	publisher := receipt.Publisher{
		Issuer: issuer,
		Sub:    sub,
	}

	// Read body (limited to MaxBodySize)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// Detect content type
	contentType := r.Header.Get("Content-Type")
	isDSSE := contentType == ContentTypeDSSE

	var subjectID string
	var receiptBytes []byte
	var dsseBytes []byte
	var dsseChannelReceiptBytes []byte
	var artifactType string

	// Compute content digest for the ingested event
	hash := sha256.Sum256(body)
	contentDigest := hex.EncodeToString(hash[:])

	// Subject ID comes from X-Subject-ID header (required for all ingest requests).
	// The SubjectIDExtractor middleware already validated it and set it in context
	// for Cedar authorization. We read it from the header here for use in receipt wrapping.
	subjectID = r.Header.Get(HeaderSubjectID)
	if subjectID == "" {
		http.Error(w, "Missing X-Subject-ID header", http.StatusBadRequest)
		return
	}
	if err := locker.ValidateSubjectID(subjectID); err != nil {
		http.Error(w, fmt.Sprintf("Invalid subject ID: %v", err), http.StatusBadRequest)
		return
	}

	if isDSSE {
		artifactType = "dsse"

		// Store DSSE bytes as-is
		dsseBytes = body

		// Parse DSSE to extract payloadType for DSSE channel receipt
		var dsse map[string]interface{}
		if err := json.Unmarshal(body, &dsse); err != nil {
			http.Error(w, "Invalid DSSE envelope", http.StatusBadRequest)
			return
		}

		payloadType, ok := dsse["payloadType"].(string)
		if !ok {
			payloadType = "application/vnd.in-toto+json" // default
		}

		// Compute DSSE digest for DSSE channel receipt (hex format, same as worker/locker)
		h := sha256.Sum256(body)
		dsseDigest := hex.EncodeToString(h[:])

		// Build DSSE channel receipt (index will be set by ingest worker after sealing)
		// For now, use -1 as a placeholder
		dsseChannelReceiptBytes, err = receipt.BuildDSSEChannelReceipt(dsseDigest, -1, publisher, subjectID, payloadType)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to build DSSE channel receipt: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// For JSON, parse body and verify subject ID matches the header
		var artifact map[string]interface{}
		if err := json.Unmarshal(body, &artifact); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Extract subject ID from body for cross-check against header
		var bodySubjectID string
		if target, ok := artifact["target"].(map[string]interface{}); ok {
			if id, ok := target["id"].(string); ok {
				bodySubjectID = id
			}
		}
		if bodySubjectID == "" {
			if id, ok := artifact["subjectId"].(string); ok {
				bodySubjectID = id
			}
		}
		if bodySubjectID != "" && bodySubjectID != subjectID {
			http.Error(w, "X-Subject-ID header does not match artifact body", http.StatusBadRequest)
			return
		}

		// Determine artifact type
		artifactType = "unknown"
		if t, ok := artifact["type"].(string); ok {
			artifactType = t
		}

		// Wrap as receipt
		receiptBytes, err = receipt.Wrap(body, publisher, subjectID, artifactType)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to wrap receipt: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Publish ingested event (notification that artifact arrived)
	_ = h.eventPublisher.PublishEvidenceIngested(ctx, events.EvidenceIngestedData{
		ContentDigest: contentDigest,
		ArtifactType:  artifactType,
		StorageRef:    "", // populated by worker after seal
		SubjectID:     subjectID,
		Publisher:     events.PublisherIdentity{Issuer: issuer, Sub: sub},
	})

	// Generate job ID
	jobID := uuid.New()

	// Create IngestRef message
	ingestRef := IngestRef{
		JobID:                   jobID.String(),
		SubjectID:               subjectID,
		IsDSSE:                  isDSSE,
		ContentDigest:           contentDigest,
		ArtifactType:            artifactType,
		ReceiptBytes:            receiptBytes,
		DSSEBytes:               dsseBytes,
		DSSEChannelReceiptBytes: dsseChannelReceiptBytes,
	}

	refBytes, err := json.Marshal(ingestRef)
	if err != nil {
		http.Error(w, "Failed to marshal IngestRef", http.StatusInternalServerError)
		return
	}

	// Publish to JetStream
	_, err = h.js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to publish to JetStream: %v", err), http.StatusInternalServerError)
		return
	}

	// Track job as pending
	h.Jobs.Store(jobID.String(), &JobInfo{
		JobID:     jobID,
		Status:    Pending,
		SubjectID: subjectID,
	})

	// Return 202 with job ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(IngestResponse{
		JobId: types.UUID(jobID),
	})
}

// RegisterSubject handles POST /api/admin/subjects
func (h *GatewayHandler) RegisterSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req SubjectRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.SubjectId == "" {
		http.Error(w, "Missing subjectId", http.StatusBadRequest)
		return
	}
	if err := locker.ValidateSubjectID(req.SubjectId); err != nil {
		http.Error(w, "Invalid subjectId", http.StatusBadRequest)
		return
	}
	if len(req.TrustedPublishers) == 0 {
		http.Error(w, "At least one trusted publisher required", http.StatusBadRequest)
		return
	}

	// Call locker to create ledger (synchronous)
	ledgerReq := map[string]interface{}{
		"subjectId": req.SubjectId,
	}
	ledgerBody, err := json.Marshal(ledgerReq)
	if err != nil {
		http.Error(w, "Failed to marshal ledger request", http.StatusInternalServerError)
		return
	}

	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.lockerURL+"/ledgers", bytes.NewReader(ledgerBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}
	createReq.Header.Set("Content-Type", "application/json")

	lockerResp, err := h.lockerClient.Do(createReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create ledger: %v", err), http.StatusInternalServerError)
		return
	}
	defer lockerResp.Body.Close()

	if lockerResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(lockerResp.Body)
		http.Error(w, fmt.Sprintf("Locker returned error: %s", string(body)), lockerResp.StatusCode)
		return
	}

	// Wrap registration as a receipt
	regData := map[string]interface{}{
		"subjectId":         req.SubjectId,
		"trustedPublishers": req.TrustedPublishers,
	}
	regBytes, err := json.Marshal(regData)
	if err != nil {
		http.Error(w, "Failed to marshal registration", http.StatusInternalServerError)
		return
	}

	// Use first publisher as the one performing registration
	publisher := receipt.Publisher{
		Issuer: req.TrustedPublishers[0].Issuer,
		Sub:    req.TrustedPublishers[0].Sub,
	}

	receiptBytes, err := receipt.Wrap(regBytes, publisher, req.SubjectId, "subject-registration")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to wrap registration receipt: %v", err), http.StatusInternalServerError)
		return
	}

	// Seal registration to locker
	sealReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.lockerURL+"/ledgers/"+req.SubjectId+"/seal", bytes.NewReader(receiptBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create seal request: %v", err), http.StatusInternalServerError)
		return
	}
	sealReq.Header.Set("Content-Type", "application/json")

	sealResp, err := h.lockerClient.Do(sealReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to seal registration: %v", err), http.StatusInternalServerError)
		return
	}
	defer sealResp.Body.Close()

	if sealResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(sealResp.Body)
		http.Error(w, fmt.Sprintf("Seal failed: %s", string(body)), sealResp.StatusCode)
		return
	}

	// Update NATS KV trust store
	trustEntries := make([]TrustEntry, len(req.TrustedPublishers))
	for i, tp := range req.TrustedPublishers {
		trustEntries[i] = TrustEntry(tp)
	}

	if err := h.trustStore.SetPublisherTrust(ctx, req.SubjectId, trustEntries); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update trust store: %v", err), http.StatusInternalServerError)
		return
	}

	// Register subject in subject registry
	if err := h.trustStore.RegisterSubject(ctx, req.SubjectId); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register subject: %v", err), http.StatusInternalServerError)
		return
	}

	// Publish CloudEvent
	if err := h.eventPublisher.PublishSubjectRegistered(ctx, req.SubjectId); err != nil {
		// Log error but don't fail the request
		// In production, consider retrying or using a dead-letter queue
		slog.Warn("failed to publish subject.registered event", "error", err, "subjectId", locker.SanitizeLogValue(req.SubjectId))
	}

	// Return 201
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(SubjectRegistrationResponse{
		SubjectId: req.SubjectId,
	})
}

// GetJobStatus handles GET /api/ingest/jobs/{jobId}
func (h *GatewayHandler) GetJobStatus(w http.ResponseWriter, r *http.Request, jobId types.UUID) {
	jobIDStr := uuid.UUID(jobId).String()

	value, ok := h.Jobs.Load(jobIDStr)
	if !ok {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	jobInfo := value.(*JobInfo)

	status := JobStatus{
		JobId:  jobId,
		Status: jobInfo.Status,
	}

	if jobInfo.Digest != nil {
		status.Digest = jobInfo.Digest
	}
	if jobInfo.LogIndex != nil {
		status.LogIndex = jobInfo.LogIndex
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

// HealthCheck handles GET /healthz
func (h *GatewayHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// UpdateJobStatus updates a job's status. This would be called by the ingest worker.
func (h *GatewayHandler) UpdateJobStatus(jobID string, status JobStatusStatus, digest *string, logIndex *int64) {
	value, ok := h.Jobs.Load(jobID)
	if !ok {
		return
	}

	jobInfo := value.(*JobInfo)
	jobInfo.Status = status
	jobInfo.Digest = digest
	jobInfo.LogIndex = logIndex
	h.Jobs.Store(jobID, jobInfo)
}
