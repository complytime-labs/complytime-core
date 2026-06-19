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
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// TesseraReader fetches raw entries from the transparency log by index.
type TesseraReader interface {
	Read(ctx context.Context, index uint64) ([]byte, error)
}

type ingestOutcome int

const (
	outcomeAck  ingestOutcome = iota
	outcomeNak
	outcomeTerm
)

const nakDelay = 5 * time.Second

// IngestWorker returns an IngestMsgHandler for the JetStream durable consumer.
// It fetches YAML from Tessera by log_index, detects the artifact type,
// processes target registrations (NATS KV), and publishes events.
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

		yaml, err := reader.Read(ctx, ref.LogIndex)
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

		artifactType, err := evidence.DetectArtifactType(yaml)
		if err != nil {
			typeStr := evidence.DetectArtifactTypeString(yaml)
			if typeStr == "TargetRegistration" {
				applyOutcome(msg, handleTargetRegistrationJS(ctx, ref, yaml, stores.Targets, stores.TrustedPublishers, pub, tracker))
				return
			}
			tracker.Fail(ref.JobID, fmt.Sprintf("invalid artifact: %v", err))
			slog.Warn("async ingest: invalid artifact", "job_id", ref.JobID, "error", err)
			_ = msg.Term()
			return
		}

		switch artifactType {
		case gemara.EvaluationLogArtifact, gemara.EnforcementLogArtifact:
			applyOutcome(msg, handleEvidenceIngestJS(ref, yaml, artifactType, pub, tracker))
		case gemara.PolicyArtifact, gemara.ControlCatalogArtifact, gemara.ThreatCatalogArtifact,
			gemara.RiskCatalogArtifact, gemara.GuidanceCatalogArtifact, gemara.MappingDocumentArtifact:
			applyOutcome(msg, handleArtifactEventJS(ref, artifactType, pub, tracker))
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

	if pub != nil && policyID != "" {
		pub.PublishEvidence(policyID, 1)
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
	artifactType gemara.ArtifactType,
	pub EventPublisher,
	tracker *IngestTracker,
) ingestOutcome {
	artType := artifactType.String()

	if artifactType == gemara.PolicyArtifact && pub != nil {
		pub.PublishPolicyNew(ref.LogIndex, ref.JobID)
	}

	tracker.CompleteArtifact(ref.JobID, ref.JobID, artType)
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", artType,
	)
	return outcomeAck
}

func handleTargetRegistrationJS(
	ctx context.Context,
	ref bus.IngestRef,
	yaml []byte,
	targets requirements.TargetStore,
	trustedPubs requirements.TrustedPublisherStore,
	pub EventPublisher,
	tracker *IngestTracker,
) ingestOutcome {
	reg, err := evidence.ParseTargetRegistration(yaml)
	if err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("parse failed: %v", err))
		slog.Warn("async ingest: TargetRegistration parse failed", "job_id", ref.JobID, "error", err)
		return outcomeTerm
	}

	if err := evidence.ValidateTargetRegistration(reg); err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("validation failed: %v", err))
		slog.Warn("async ingest: TargetRegistration validation failed", "job_id", ref.JobID, "error", err)
		return outcomeTerm
	}

	registeredAt, err := time.Parse(time.RFC3339, reg.Metadata.Date)
	if err != nil {
		registeredAt = time.Now().UTC()
	}

	row := requirements.TargetRow{
		TargetID:        reg.Target.ID,
		TesseraLogIndex: ref.LogIndex,
		TargetName:      reg.Target.Name,
		TargetType:      reg.Target.Type,
		Technologies:    requirements.NormalizeSlice(reg.Dimensions.Technologies),
		Geopolitical:    requirements.NormalizeSlice(reg.Dimensions.Geopolitical),
		Sensitivity:     requirements.NormalizeSlice(reg.Dimensions.Sensitivity),
		Users:           requirements.NormalizeSlice(reg.Dimensions.Users),
		Groups:          requirements.NormalizeSlice(reg.Dimensions.Groups),
		RegisteredAt:    registeredAt,
		RegisteredBy:    ref.PublisherIdentity.Sub,
	}

	if err := targets.InsertTarget(ctx, row); err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("insert failed: %v", err))
		slog.Error("async ingest: TargetRegistration insert failed", "job_id", ref.JobID, "error", err)
		return outcomeNak
	}

	if len(reg.Target.TrustedPublishers) > 0 && trustedPubs != nil {
		logIdx := int64(ref.LogIndex) //nolint:gosec
		addedBy := ref.PublisherIdentity.Sub
		pubRows := make([]requirements.TrustedPublisherRow, len(reg.Target.TrustedPublishers))
		for i, p := range reg.Target.TrustedPublishers {
			pubRows[i] = requirements.TrustedPublisherRow{
				TargetID:        reg.Target.ID,
				Issuer:          p.Issuer,
				SubPattern:      p.SubPattern,
				AddedAt:         registeredAt,
				AddedBy:         &addedBy,
				TesseraLogIndex: &logIdx,
			}
			if p.Environment != "" {
				env := p.Environment
				pubRows[i].Environment = &env
			}
		}
		if err := trustedPubs.InsertTrustedPublishers(ctx, pubRows); err != nil {
			tracker.Fail(ref.JobID, fmt.Sprintf("insert trusted publishers failed: %v", err))
			slog.Error("async ingest: trusted publishers insert failed", "job_id", ref.JobID, "error", err)
			return outcomeNak
		}
		slog.Info("trusted publishers added", "job_id", ref.JobID, "target_id", reg.Target.ID, "count", len(pubRows))
	}

	if len(reg.Target.RemovePublishers) > 0 && trustedPubs != nil {
		keys := make([]requirements.TrustedPublisherKey, len(reg.Target.RemovePublishers))
		for i, p := range reg.Target.RemovePublishers {
			keys[i] = requirements.TrustedPublisherKey{
				Issuer:     p.Issuer,
				SubPattern: p.SubPattern,
			}
		}
		if err := trustedPubs.RemoveTrustedPublishers(ctx, reg.Target.ID, keys, ref.LogIndex); err != nil {
			tracker.Fail(ref.JobID, fmt.Sprintf("remove trusted publishers failed: %v", err))
			slog.Error("async ingest: trusted publishers remove failed", "job_id", ref.JobID, "error", err)
			return outcomeNak
		}
		slog.Info("trusted publishers removed", "job_id", ref.JobID, "target_id", reg.Target.ID, "count", len(keys))
	}

	if pub != nil {
		pub.PublishTargetRegistered(ref.LogIndex, reg.Target.ID, ref.PublisherIdentity.Sub)
	}

	tracker.CompleteArtifact(ref.JobID, reg.Target.ID, "TargetRegistration")
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", "TargetRegistration",
		"target_id", reg.Target.ID,
	)
	return outcomeAck
}

func isNotYetIntegrated(err error) bool {
	return strings.Contains(err.Error(), "not yet integrated")
}
