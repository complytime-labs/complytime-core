// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gemara "github.com/gemaraproj/go-gemara"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/receipt"
)

// TesseraReader fetches raw entries from the transparency log by index.
type TesseraReader interface {
	Read(ctx context.Context, index uint64) ([]byte, error)
}

type ingestOutcome int

const (
	outcomeAck ingestOutcome = iota
	outcomeNak
	outcomeTerm
)

const nakDelay = 5 * time.Second

// unwrapEntry detects the Tessera entry format and extracts the artifact content.
// Handles three formats: receipt (in-toto Statement), DSSE envelope, legacy raw YAML.
func unwrapEntry(data []byte) (content []byte, pub bus.PublisherIdentity, isDSSE bool, err error) {
	if receipt.IsReceipt(data) {
		pred, err := receipt.Unwrap(data)
		if err != nil {
			return nil, bus.PublisherIdentity{}, false, fmt.Errorf("unwrap receipt: %w", err)
		}
		return []byte(pred.Content), bus.PublisherIdentity{
			Sub:      pred.Publisher.Subject,
			Issuer:   pred.Publisher.Issuer,
			Type:     inferPublisherType(pred.Publisher.Subject),
			Verified: true,
		}, false, nil
	}

	if receipt.IsDSSE(data) {
		payload, err := receipt.DecodeDSSEPayload(data)
		if err != nil {
			return nil, bus.PublisherIdentity{}, true, err
		}
		return payload, bus.PublisherIdentity{}, true, nil
	}

	// Legacy raw YAML
	return data, bus.PublisherIdentity{}, false, nil
}

// IngestWorker returns an IngestMsgHandler for the JetStream durable consumer.
// It fetches entries from Tessera by log_index, unwraps receipts/DSSE envelopes,
// detects the artifact type, and publishes events.
func IngestWorker(
	ctx context.Context,
	stores Stores,
	pub EventPublisher,
	tracker *IngestTracker,
	reader TesseraReader,
) bus.IngestMsgHandler {
	return func(_ context.Context, ref bus.IngestRef, msg jetstream.Msg) {
		_ = msg.InProgress()
		slog.Info("async ingest started", "job_id", ref.JobID, "log_index", ref.LogIndex)

		raw, err := reader.Read(ctx, ref.LogIndex)
		if err != nil {
			if isNotYetIntegrated(err) {
				slog.Warn("tessera entry not yet integrated, will retry",
					"job_id", ref.JobID, "log_index", ref.LogIndex)
				_ = msg.NakWithDelay(nakDelay)
				return
			}
			tracker.Fail(ref.JobID, fmt.Sprintf("tessera read failed: %v", err))
			slog.Error("async ingest: tessera read failed", "job_id", ref.JobID, "error", err)
			_ = msg.Term()
			return
		}

		content, entryPub, _, err := unwrapEntry(raw)
		if err != nil {
			tracker.Fail(ref.JobID, fmt.Sprintf("unwrap entry: %v", err))
			slog.Error("async ingest: unwrap failed", "job_id", ref.JobID, "error", err)
			_ = msg.Term()
			return
		}

		// Use publisher identity from receipt if available, fall back to IngestRef
		if entryPub.Sub != "" {
			ref.PublisherIdentity = entryPub
		}

		artifactType, err := evidence.DetectArtifactType(content)
		if err != nil {
			if evidence.DetectArtifactTypeString(content) == "TargetRegistration" {
				slog.Info("skipping legacy TargetRegistration entry", "job_id", ref.JobID)
				tracker.CompleteArtifact(ref.JobID, fmt.Sprintf("log:%d", ref.LogIndex), "TargetRegistration")
				_ = msg.Ack()
				return
			}
			tracker.Fail(ref.JobID, fmt.Sprintf("invalid artifact: %v", err))
			slog.Warn("async ingest: invalid artifact", "job_id", ref.JobID, "error", err)
			_ = msg.Term()
			return
		}

		switch artifactType {
		case gemara.EvaluationLogArtifact, gemara.EnforcementLogArtifact:
			applyOutcome(msg, handleEvidenceIngestJS(ref, content, artifactType, pub, tracker))
		case gemara.PolicyArtifact, gemara.ControlCatalogArtifact, gemara.ThreatCatalogArtifact,
			gemara.RiskCatalogArtifact, gemara.GuidanceCatalogArtifact, gemara.MappingDocumentArtifact:
			applyOutcome(msg, handleArtifactEventJS(ref, content, artifactType, pub, tracker))
		default:
			tracker.Fail(ref.JobID, fmt.Sprintf("unsupported artifact type: %s", artifactType))
			_ = msg.Term()
		}
	}
}

func applyOutcome(msg jetstream.Msg, outcome ingestOutcome) {
	switch outcome {
	case outcomeAck:
		_ = msg.Ack()
	case outcomeNak:
		_ = msg.NakWithDelay(nakDelay)
	case outcomeTerm:
		_ = msg.Term()
	}
}

func handleEvidenceIngestJS(
	ref bus.IngestRef,
	yaml []byte,
	artifactType gemara.ArtifactType,
	pub EventPublisher,
	tracker *IngestTracker,
) ingestOutcome {
	policyID := evidence.DetectPolicyID(yaml)
	targetID := evidence.DetectTargetID(yaml)

	if pub != nil && policyID != "" {
		pub.PublishEvidence(policyID, targetID, artifactType.String(), 1, ref.LogIndex)
	}

	tracker.Complete(ref.JobID, 1, policyID)
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", artifactType,
		"policy_id", policyID,
	)
	return outcomeAck
}

func handleArtifactEventJS(
	ref bus.IngestRef,
	content []byte,
	artifactType gemara.ArtifactType,
	pub EventPublisher,
	tracker *IngestTracker,
) ingestOutcome {
	artType := artifactType.String()
	targetID := evidence.DetectTargetID(content)

	if artifactType == gemara.PolicyArtifact && pub != nil {
		pub.PublishPolicyNew(ref.LogIndex, evidence.DetectPolicyID(content), targetID)
	}

	artifactID := fmt.Sprintf("log:%d", ref.LogIndex)
	tracker.CompleteArtifact(ref.JobID, artifactID, artType)
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", artType,
	)
	return outcomeAck
}

func isNotYetIntegrated(err error) bool {
	return strings.Contains(err.Error(), "not yet integrated")
}
