// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"fmt"
	"io"

	gemara "github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"

	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/ingest"
)

// toEvidenceRecords converts ingest EvidenceRows to store EvidenceRecords.
// Deprecated: use toEvidenceRecordsWithLogIndex instead. This function is kept for
// backward compatibility and will be removed in a future version.
func toEvidenceRecords(rows []ingest.EvidenceRow) []EvidenceRecord {
	return toEvidenceRecordsWithLogIndex(rows, 0, nil)
}

// toEvidenceRecordsWithLogIndex converts ingest EvidenceRows to store EvidenceRecords,
// optionally setting a log_index and publisher identity for all records (for Tessera transparency log tracking).
func toEvidenceRecordsWithLogIndex(rows []ingest.EvidenceRow, logIndex uint64, publisherIdentity *events.PublisherIdentity) []EvidenceRecord {
	records := make([]EvidenceRecord, len(rows))
	for i, row := range rows {
		rec := EvidenceRecord{
			EvidenceID:           row.EvidenceID,
			PolicyID:             derefStr(row.PolicyID),
			TargetID:             row.TargetID,
			TargetName:           derefStr(row.TargetName),
			TargetType:           derefStr(row.TargetType),
			TargetEnv:            derefStr(row.TargetEnv),
			EngineName:           derefStr(row.EngineName),
			EngineVersion:        derefStr(row.EngineVersion),
			RuleID:               row.RuleID,
			RuleName:             derefStr(row.RuleName),
			RuleURI:              derefStr(row.RuleURI),
			EvalResult:           row.EvalResult,
			EvalMessage:          derefStr(row.EvalMessage),
			ControlID:            derefStr(row.ControlID),
			ControlCatalogID:     derefStr(row.ControlCatalogID),
			ControlCategory:      derefStr(row.ControlCategory),
			ControlApplicability: row.ControlApplicability,
			RequirementID:        derefStr(row.RequirementID),
			PlanID:               derefStr(row.PlanID),
			Confidence:           derefStr(row.Confidence),
			StepsExecuted:        derefUint16(row.StepsExecuted),
			ComplianceStatus:     row.ComplianceStatus,
			RiskLevel:            derefStr(row.RiskLevel),
			Frameworks:           row.Frameworks,
			Requirements:         row.Requirements,
			RemediationAction:    derefStr(row.RemediationAction),
			RemediationStatus:    derefStr(row.RemediationStatus),
			RemediationDesc:      derefStr(row.RemediationDesc),
			ExceptionID:          derefStr(row.ExceptionID),
			ExceptionActive:      row.ExceptionActive,
			EnrichmentStatus:     row.EnrichmentStatus,
			AttestationRef:       derefStr(row.AttestationRef),
			SourceRegistry:       derefStr(row.SourceRegistry),
			BlobRef:              derefStr(row.BlobRef),
			Certified:            row.Certified,
			CollectedAt:          row.CollectedAt,
		}
		// Set log_index if provided (from IngestRawEvent)
		if row.LogIndex != nil {
			rec.LogIndex = row.LogIndex
		} else if logIndex > 0 {
			v := logIndex
			rec.LogIndex = &v
		}

		// Set publisher identity if provided (from JWT-verified ingestion)
		if publisherIdentity != nil {
			rec.PublisherIssuer = publisherIdentity.Issuer
			rec.SubmittedBy = publisherIdentity.Sub
			rec.PublisherType = publisherIdentity.Type
		}

		records[i] = rec
	}
	return records
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefUint16(p *uint16) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

// detectArtifactType does a lightweight header parse to determine the type.
func detectArtifactType(data []byte) (gemara.ArtifactType, error) {
	var hdr struct {
		Metadata gemara.Metadata `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &hdr); err != nil {
		return gemara.InvalidArtifact, fmt.Errorf("parse YAML header: %w", err)
	}
	if hdr.Metadata.Type == gemara.InvalidArtifact {
		return gemara.InvalidArtifact, fmt.Errorf("missing or invalid metadata.type field")
	}
	return hdr.Metadata.Type, nil
}

func flattenEvaluation(ctx context.Context, data []byte) ([]ingest.EvidenceRow, string, error) {
	f := &bytesFetcher{data: data}
	evalLog, err := gemara.Load[gemara.EvaluationLog](ctx, f, "upload.yaml")
	if err != nil {
		return nil, "", fmt.Errorf("parse EvaluationLog: %w", err)
	}
	policyID := derivePolicyID(evalLog.Metadata.MappingReferences)
	rows, err := ingest.FlattenEvaluationLog(evalLog, policyID)
	return rows, policyID, err
}

func flattenEnforcement(ctx context.Context, data []byte) ([]ingest.EvidenceRow, string, error) {
	f := &bytesFetcher{data: data}
	enfLog, err := gemara.Load[gemara.EnforcementLog](ctx, f, "upload.yaml")
	if err != nil {
		return nil, "", fmt.Errorf("parse EnforcementLog: %w", err)
	}
	policyID := derivePolicyID(enfLog.Metadata.MappingReferences)
	rows, err := ingest.FlattenEnforcementLog(enfLog, policyID)
	return rows, policyID, err
}

// bytesFetcher satisfies gemara.Fetcher for in-memory YAML.
type bytesFetcher struct {
	data []byte
}

func (b *bytesFetcher) Fetch(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

// derivePolicyID extracts a policy reference from mapping-references.
func derivePolicyID(refs []gemara.MappingReference) string {
	for _, r := range refs {
		if r.Title == "Policy" || r.Id == "policy" {
			return r.Id
		}
	}
	if len(refs) > 0 {
		return refs[0].Id
	}
	return ""
}
