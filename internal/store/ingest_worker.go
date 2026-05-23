// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"

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

	records := toEvidenceRecordsWithLogIndex(rows, evt.LogIndex)
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
