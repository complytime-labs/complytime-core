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

// ingestOutcome classifies the result of processing an ingest message.
type ingestOutcome int

const (
	outcomeAck  ingestOutcome = iota // Success — remove from stream
	outcomeNak                       // Transient failure — retry after delay
	outcomeTerm                      // Permanent failure — no more retries
)

const nakDelay = 5 * time.Second

// IngestWorker returns an IngestMsgHandler for the JetStream durable consumer.
// It fetches YAML from Tessera by log_index, processes the artifact, and
// acks/naks/terms the JetStream message based on the outcome.
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

		is := requirements.ImportStores{
			Catalogs: stores.Catalogs,
			Controls: stores.Controls,
			Threats:  stores.Threats,
			Risks:    stores.Risks,
			Guidance: stores.Guidance,
		}

		var result ingestOutcome
		switch artifactType {
		case gemara.EvaluationLogArtifact:
			result = handleEvidenceIngestJS(ctx, ref, yaml, gemara.EvaluationLogArtifact,
				stores.Evidence, pub, tracker)
		case gemara.EnforcementLogArtifact:
			result = handleEvidenceIngestJS(ctx, ref, yaml, gemara.EnforcementLogArtifact,
				stores.Evidence, pub, tracker)
		case gemara.PolicyArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StorePolicyFromContent(ctx, stores.Policies, stores.Controls,
					string(yaml), requirements.PolicyIngestOption{
						LogIndex: ref.LogIndex,
						BundleID: ref.BundleID,
					})
				if err == nil && pub != nil {
					pub.PublishPolicyNew(ref.LogIndex, art.ID)
				}
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.ControlCatalogArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StoreCatalogFromContent(ctx, is, "ControlCatalog", string(yaml))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.ThreatCatalogArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StoreCatalogFromContent(ctx, is, "ThreatCatalog", string(yaml))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.RiskCatalogArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StoreCatalogFromContent(ctx, is, "RiskCatalog", string(yaml))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.GuidanceCatalogArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StoreCatalogFromContent(ctx, is, "GuidanceCatalog", string(yaml))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.MappingDocumentArtifact:
			result = handleArtifactStoreJS(ctx, ref, tracker, func() (string, string, error) {
				art, err := requirements.StoreMappingFromContent(ctx, stores.Mappings, string(yaml))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		default:
			tracker.Fail(ref.JobID, fmt.Sprintf("unsupported artifact type: %s", artifactType))
			_ = msg.Term()
			return
		}

		applyOutcome(msg, result)
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
	ctx context.Context,
	ref bus.IngestRef,
	yaml []byte,
	artifactType gemara.ArtifactType,
	evidenceStore evidence.EvidenceStore,
	pub EventPublisher,
	tracker *IngestTracker,
) ingestOutcome {
	var rows []evidence.EvidenceRow
	var policyID string
	var err error

	switch artifactType {
	case gemara.EvaluationLogArtifact:
		rows, policyID, err = evidence.FlattenEvaluation(ctx, yaml)
	case gemara.EnforcementLogArtifact:
		rows, policyID, err = evidence.FlattenEnforcement(ctx, yaml)
	}
	if err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("flatten failed: %v", err))
		slog.Warn("async ingest: flatten failed", "job_id", ref.JobID, "error", err)
		return outcomeTerm // Parse/flatten is permanent — invalid YAML won't fix on retry
	}

	records := evidence.ToEvidenceRecordsWithLogIndex(rows, &ref.LogIndex, &ref.PublisherIdentity)
	count, err := evidenceStore.InsertEvidence(ctx, records)
	if err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("insert failed: %v", err))
		slog.Error("async ingest: insert failed", "job_id", ref.JobID, "error", err)
		return outcomeNak // Store failure is transient (PG timeout, connection reset)
	}

	if pub != nil && count > 0 && policyID != "" {
		pub.PublishEvidence(policyID, count)
	}

	tracker.Complete(ref.JobID, count, policyID)
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", artifactType,
		"inserted", count,
		"policy_id", policyID,
	)
	return outcomeAck
}

func handleArtifactStoreJS(
	ctx context.Context,
	ref bus.IngestRef,
	tracker *IngestTracker,
	storeFn func() (string, string, error),
	bundleStore func(context.Context, requirements.BundleArtifactRow) error,
) ingestOutcome {
	id, artType, err := storeFn()
	if err != nil {
		tracker.Fail(ref.JobID, fmt.Sprintf("store failed: %v", err))
		slog.Warn("async ingest: store failed", "job_id", ref.JobID, "error", err)
		return outcomeNak // Store failure is transient
	}

	if ref.BundleID != "" && bundleStore != nil {
		if err := bundleStore(ctx, requirements.BundleArtifactRow{
			BundleID:        ref.BundleID,
			TesseraLogIndex: ref.LogIndex,
			ArtifactType:    artType,
			ArtifactID:      id,
			OCIReference:    ref.OCIReference,
		}); err != nil {
			slog.Warn("bundle artifact tracking failed", "bundle_id", ref.BundleID, "error", err)
		}
	}

	tracker.CompleteArtifact(ref.JobID, id, artType)
	slog.Info("async ingest completed",
		"job_id", ref.JobID,
		"type", artType,
		"artifact_id", id,
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

	// Process trusted-publishers additions
	if len(reg.Target.TrustedPublishers) > 0 && trustedPubs != nil {
		logIdx := int64(ref.LogIndex)
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

	// Process remove-publishers removals
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
