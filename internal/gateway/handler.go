package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oapi-codegen/runtime/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"

	"github.com/complytime-labs/complytime-core/events"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/complytime-labs/complytime-core/internal/ingest"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/subjects"
	"github.com/complytime-labs/complytime-core/internal/trust"
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
	trustStore     *trust.TrustStore
	js             jetstream.JetStream
	eventPublisher *eventspkg.EventPublisher
	schemas        *SchemaRegistry
}

// NewHandler creates a new GatewayHandler with dependencies.
func NewHandler(
	trustStore *trust.TrustStore,
	js jetstream.JetStream,
	eventPublisher *eventspkg.EventPublisher,
	schemas *SchemaRegistry,
) *GatewayHandler {
	return &GatewayHandler{
		trustStore:     trustStore,
		js:             js,
		eventPublisher: eventPublisher,
		schemas:        schemas,
	}
}

// IngestArtifact handles POST /api/ingest
func (h *GatewayHandler) IngestArtifact(w http.ResponseWriter, r *http.Request) {
	initTelemetry()

	ctx, span := otel.Tracer("complytime-gateway").Start(r.Context(), "gateway.ingest")
	defer span.End()

	start := time.Now()

	// Get publisher from context
	issuer, sub := authz.GetPublisher(ctx)
	if issuer == "" || sub == "" {
		span.SetStatus(codes.Error, "missing publisher identity")
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
		span.SetStatus(codes.Error, "failed to read request body")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		span.SetStatus(codes.Error, "empty request body")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// Compute content digest for the ingested event
	hash := sha256.Sum256(body)
	contentDigest := hex.EncodeToString(hash[:])

	// Subject ID comes from X-Subject-ID header (required for all ingest requests).
	// The SubjectIDExtractor middleware already validated it and set it in context
	// for Cedar authorization. We read it from the header here for use in receipt wrapping.
	subjectID := r.Header.Get(HeaderSubjectID)
	if subjectID == "" {
		span.SetStatus(codes.Error, "missing subject ID")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
		http.Error(w, "Missing X-Subject-ID header", http.StatusBadRequest)
		return
	}
	if err := subjects.ValidateSubjectID(subjectID); err != nil {
		span.SetStatus(codes.Error, "invalid subject ID")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
		http.Error(w, fmt.Sprintf("Invalid subject ID: %v", err), http.StatusBadRequest)
		return
	}

	// Determine artifact type based on content type
	var artifactType string
	contentType := r.Header.Get("Content-Type")
	isDSSE := contentType == ContentTypeDSSE

	if isDSSE {
		artifactType = "dsse"
	} else {
		// For JSON, parse body and verify subject ID matches the header
		var artifact map[string]interface{}
		if err := json.Unmarshal(body, &artifact); err != nil {
			span.SetStatus(codes.Error, "invalid JSON")
			ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
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
			span.SetStatus(codes.Error, "subject ID mismatch")
			ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", "unknown")))
			http.Error(w, "X-Subject-ID header does not match artifact body", http.StatusBadRequest)
			return
		}

		// Extract artifact type from metadata.type, fall back to top-level type
		artifactType = "unknown"
		if metadata, ok := artifact["metadata"].(map[string]interface{}); ok {
			if t, ok := metadata["type"].(string); ok {
				artifactType = t
			}
		}
		// Fall back to top-level type for backward compat
		if artifactType == "unknown" {
			if t, ok := artifact["type"].(string); ok {
				artifactType = t
			}
		}

		// Validate Gemara artifacts (skip DSSE, which are opaque signed envelopes)
		if err := h.schemas.Validate(body); err != nil {
			span.SetStatus(codes.Error, "validation failed")
			ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", artifactType)))
			if ve, ok := err.(*validationError); ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(ve.ValidationError)
				return
			}
			// Unexpected validation error
			http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Wrap as receipt (unified path for all artifact types)
	receiptBytes, err := receipt.Wrap(body, publisher, subjectID, artifactType)
	if err != nil {
		span.SetStatus(codes.Error, "failed to wrap receipt")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", artifactType)))
		http.Error(w, fmt.Sprintf("Failed to wrap receipt: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate job ID (correlation ID for logs/CloudEvents)
	jobID := uuid.New()

	// Create IngestRef message
	ingestRef := ingest.IngestRef{
		JobID:         jobID.String(),
		SubjectID:     subjectID,
		ContentDigest: contentDigest,
		ArtifactType:  artifactType,
		ReceiptBytes:  receiptBytes,
	}

	refBytes, err := json.Marshal(ingestRef)
	if err != nil {
		span.SetStatus(codes.Error, "failed to marshal IngestRef")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", artifactType)))
		http.Error(w, "Failed to marshal IngestRef", http.StatusInternalServerError)
		return
	}

	// Publish to JetStream
	_, err = h.js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	if err != nil {
		span.SetStatus(codes.Error, "failed to publish to JetStream")
		ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "rejected"), attribute.String("artifactType", artifactType)))
		http.Error(w, fmt.Sprintf("Failed to publish to JetStream: %v", err), http.StatusInternalServerError)
		return
	}

	// Publish ingested event after successful NATS publish
	_ = h.eventPublisher.PublishEvidenceIngested(ctx, events.EvidenceIngestedData{
		ContentDigest: contentDigest,
		ArtifactType:  artifactType,
		StorageRef:    "", // populated by locker after seal
		SubjectID:     subjectID,
		Publisher:     events.PublisherIdentity{Issuer: issuer, Sub: sub},
	})

	// Record successful ingest metrics
	span.SetAttributes(
		attribute.String("subjectId", subjectID),
		attribute.String("artifactType", artifactType),
		attribute.String("contentDigest", contentDigest),
	)
	ingestTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("status", "accepted"), attribute.String("artifactType", artifactType)))
	ingestDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.String("artifactType", artifactType)))

	// Return 202 with job ID (correlation ID for logs/CloudEvents)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(IngestResponse{
		JobId: types.UUID(jobID),
	})
}

// HealthCheck handles GET /healthz
func (h *GatewayHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}
