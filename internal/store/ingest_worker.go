// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gemara "github.com/gemaraproj/go-gemara"

	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/ingest"
)

func IngestWorker(
	ctx context.Context,
	stores Stores,
	pub EventPublisher,
	tracker *IngestTracker,
) func(events.IngestRawEvent) {
	return func(evt events.IngestRawEvent) {
		slog.Info("async ingest started", "job_id", evt.JobID)

		artifactType, err := detectArtifactType(evt.YAML)
		if err != nil {
			// Fall back to string-based detection for CUE extensions
			typeStr := detectArtifactTypeString(evt.YAML)
			if typeStr == "TargetRegistration" {
				handleTargetRegistration(ctx, evt, stores.Targets, pub, tracker)
				return
			}
			tracker.Fail(evt.JobID, fmt.Sprintf("invalid artifact: %v", err))
			slog.Warn("async ingest: invalid artifact", "job_id", evt.JobID, "error", err)
			return
		}

		switch artifactType {
		case gemara.EvaluationLogArtifact:
			handleEvidenceIngest(ctx, evt, gemara.EvaluationLogArtifact, stores.Evidence,
				pub, tracker)
		case gemara.EnforcementLogArtifact:
			handleEvidenceIngest(ctx, evt, gemara.EnforcementLogArtifact, stores.Evidence,
				pub, tracker)
	case gemara.PolicyArtifact:
		handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
			art, err := storePolicyFromContent(ctx, stores.Policies, stores.Controls,
				string(evt.YAML), policyIngestOption{
					LogIndex: evt.LogIndex,
					BundleID: evt.BundleID,
				})
			if err == nil && pub != nil {
				pub.PublishPolicyNew(evt.LogIndex, art.ID)
			}
			return art.ID, art.Type, err
		}, stores.InsertBundleArtifact)
		case gemara.ControlCatalogArtifact:
			handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "ControlCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.ThreatCatalogArtifact:
			handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "ThreatCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.RiskCatalogArtifact:
			handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "RiskCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.GuidanceCatalogArtifact:
			handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "GuidanceCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		case gemara.MappingDocumentArtifact:
			handleArtifactStore(ctx, evt, tracker, func() (string, string, error) {
				art, err := storeMappingFromContent(ctx, stores.Mappings, string(evt.YAML))
				return art.ID, art.Type, err
			}, stores.InsertBundleArtifact)
		default:
			tracker.Fail(evt.JobID, fmt.Sprintf("unsupported artifact type: %s",
				artifactType))
		}
	}
}

func handleEvidenceIngest(
	ctx context.Context,
	evt events.IngestRawEvent,
	artifactType gemara.ArtifactType,
	evidence EvidenceStore,
	pub EventPublisher,
	tracker *IngestTracker,
) {
	var rows []ingest.EvidenceRow
	var policyID string
	var err error

	switch artifactType {
	case gemara.EvaluationLogArtifact:
		rows, policyID, err = flattenEvaluation(ctx, evt.YAML)
	case gemara.EnforcementLogArtifact:
		rows, policyID, err = flattenEnforcement(ctx, evt.YAML)
	}
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("flatten failed: %v", err))
		slog.Warn("async ingest: flatten failed", "job_id", evt.JobID, "error", err)
		return
	}

	records := toEvidenceRecordsWithLogIndex(rows, evt.LogIndex, &evt.PublisherIdentity)
	count, err := evidence.InsertEvidence(ctx, records)
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("insert failed: %v", err))
		slog.Error("async ingest: insert failed", "job_id", evt.JobID, "error", err)
		return
	}

	if pub != nil && count > 0 && policyID != "" {
		pub.PublishEvidence(policyID, count)
	}

	tracker.Complete(evt.JobID, count, policyID)
	slog.Info("async ingest completed",
		"job_id", evt.JobID,
		"type", artifactType,
		"inserted", count,
		"policy_id", policyID,
	)
}

func handleArtifactStore(
	ctx context.Context,
	evt events.IngestRawEvent,
	tracker *IngestTracker,
	storeFn func() (string, string, error),
	bundleStore func(context.Context, BundleArtifactRow) error,
) {
	id, artType, err := storeFn()
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("store failed: %v", err))
		slog.Warn("async ingest: store failed", "job_id", evt.JobID, "error", err)
		return
	}

	if evt.BundleID != "" && bundleStore != nil {
		if err := bundleStore(ctx, BundleArtifactRow{
			BundleID:        evt.BundleID,
			TesseraLogIndex: evt.LogIndex,
			ArtifactType:    artType,
			ArtifactID:      id,
			OCIReference:    evt.OCIReference,
		}); err != nil {
			slog.Warn("bundle artifact tracking failed", "bundle_id", evt.BundleID, "error", err)
		}
	}

	tracker.CompleteArtifact(evt.JobID, id, artType)
	slog.Info("async ingest completed",
		"job_id", evt.JobID,
		"type", artType,
		"artifact_id", id,
	)
}

func handleTargetRegistration(
	ctx context.Context,
	evt events.IngestRawEvent,
	targets TargetStore,
	pub EventPublisher,
	tracker *IngestTracker,
) {
	reg, err := parseTargetRegistration(evt.YAML)
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("parse failed: %v", err))
		slog.Warn("async ingest: TargetRegistration parse failed", "job_id", evt.JobID, "error", err)
		return
	}

	registeredAt, err := time.Parse(time.RFC3339, reg.Metadata.Date)
	if err != nil {
		registeredAt = time.Now().UTC()
	}

	// Normalize nil slices to empty slices for database insert
	// (nil slice is treated as NULL which violates NOT NULL constraint)
	row := TargetRow{
		TargetID:        reg.Target.ID,
		TesseraLogIndex: evt.LogIndex,
		TargetName:      reg.Target.Name,
		TargetType:      reg.Target.Type,
		Technologies:    normalizeSlice(reg.Dimensions.Technologies),
		Geopolitical:    normalizeSlice(reg.Dimensions.Geopolitical),
		Sensitivity:     normalizeSlice(reg.Dimensions.Sensitivity),
		Users:           normalizeSlice(reg.Dimensions.Users),
		Groups:          normalizeSlice(reg.Dimensions.Groups),
		RegisteredAt:    registeredAt,
		RegisteredBy:    evt.PublisherIdentity.Sub,
	}

	if err := targets.InsertTarget(ctx, row); err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("insert failed: %v", err))
		slog.Error("async ingest: TargetRegistration insert failed", "job_id", evt.JobID, "error", err)
		return
	}

	if pub != nil {
		pub.PublishTargetRegistered(evt.LogIndex, reg.Target.ID, evt.PublisherIdentity.Sub)
	}

	tracker.CompleteArtifact(evt.JobID, reg.Target.ID, "TargetRegistration")
	slog.Info("async ingest completed",
		"job_id", evt.JobID,
		"type", "TargetRegistration",
		"target_id", reg.Target.ID,
	)
}

// normalizeSlice returns an empty slice if the input is nil.
// This prevents nil slices from being passed as NULL to PostgreSQL
// which would violate NOT NULL constraints even when DEFAULT is set.
func normalizeSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
