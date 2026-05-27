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
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storePolicyFromContent(ctx, stores.Policies, stores.Controls,
					string(evt.YAML))
				if err == nil && pub != nil {
					pub.PublishPolicyNew(evt.LogIndex, art.ID)
				}
				return art.ID, art.Type, err
			})
		case gemara.ControlCatalogArtifact:
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "ControlCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			})
		case gemara.ThreatCatalogArtifact:
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "ThreatCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			})
		case gemara.RiskCatalogArtifact:
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "RiskCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			})
		case gemara.GuidanceCatalogArtifact:
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storeCatalogFromContent(ctx, stores, "GuidanceCatalog",
					string(evt.YAML))
				return art.ID, art.Type, err
			})
		case gemara.MappingDocumentArtifact:
			handleArtifactStore(evt, tracker, func() (string, string, error) {
				art, err := storeMappingFromContent(ctx, stores.Mappings, string(evt.YAML))
				return art.ID, art.Type, err
			})
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
	evt events.IngestRawEvent,
	tracker *IngestTracker,
	storeFn func() (string, string, error),
) {
	id, artType, err := storeFn()
	if err != nil {
		tracker.Fail(evt.JobID, fmt.Sprintf("store failed: %v", err))
		slog.Warn("async ingest: store failed", "job_id", evt.JobID, "error", err)
		return
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

	row := TargetRow{
		TargetID:        reg.Target.ID,
		TesseraLogIndex: evt.LogIndex,
		TargetName:      reg.Target.Name,
		TargetType:      reg.Target.Type,
		Technologies:    reg.Dimensions.Technologies,
		Geopolitical:    reg.Dimensions.Geopolitical,
		Sensitivity:     reg.Dimensions.Sensitivity,
		Users:           reg.Dimensions.Users,
		Groups:          reg.Dimensions.Groups,
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
