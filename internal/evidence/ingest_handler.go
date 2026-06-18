// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"fmt"
	"io"

	gemara "github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"

	"github.com/complytime-labs/complytime-core/internal/bus"
)

// ToEvidenceRecords converts ingest EvidenceRows to EvidenceRecords.
func ToEvidenceRecords(rows []EvidenceRow) []EvidenceRecord {
	return ToEvidenceRecordsWithLogIndex(rows, nil, nil)
}

// ToEvidenceRecordsWithLogIndex converts ingest EvidenceRows to EvidenceRecords,
// optionally setting a log_index and publisher identity for all records (for Tessera transparency log tracking).
func ToEvidenceRecordsWithLogIndex(rows []EvidenceRow, logIndex *uint64, publisherIdentity *bus.PublisherIdentity) []EvidenceRecord {
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
			AttestationRef:       derefStr(row.AttestationRef),
			SourceRegistry:       derefStr(row.SourceRegistry),
			BlobRef:              derefStr(row.BlobRef),
			CollectedAt:          row.CollectedAt,
		}
		// Set log_index if provided (from IngestRawEvent)
		if row.LogIndex != nil {
			rec.LogIndex = row.LogIndex
		} else if logIndex != nil {
			rec.LogIndex = logIndex
		}

		// Set publisher identity if provided (from JWT-verified ingestion)
		if publisherIdentity != nil && publisherIdentity.Verified {
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

// DetectArtifactType does a lightweight header parse to determine the type.
func DetectArtifactType(data []byte) (gemara.ArtifactType, error) {
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

// DetectArtifactTypeString returns the raw string value of metadata.type.
func DetectArtifactTypeString(data []byte) string {
	var hdr struct {
		Metadata struct {
			Type string `yaml:"type"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &hdr); err != nil {
		return ""
	}
	return hdr.Metadata.Type
}

// TrustedPublisherYAML represents a trusted publisher entry in the YAML.
type TrustedPublisherYAML struct {
	Issuer      string `yaml:"issuer"`
	SubPattern  string `yaml:"sub_pattern"`
	Environment string `yaml:"environment"`
}

// RemovePublisherYAML represents a publisher to remove in the YAML.
type RemovePublisherYAML struct {
	Issuer     string `yaml:"issuer"`
	SubPattern string `yaml:"sub_pattern"`
}

// TargetRegistrationYAML represents the parsed TargetRegistration artifact.
type TargetRegistrationYAML struct {
	Metadata struct {
		Type string `yaml:"type"`
		ID   string `yaml:"id"`
		Date string `yaml:"date"`
	} `yaml:"metadata"`
	Target struct {
		ID                string                 `yaml:"id"`
		Name              string                 `yaml:"name"`
		Type              string                 `yaml:"type"`
		TrustedPublishers []TrustedPublisherYAML `yaml:"trusted-publishers"`
		RemovePublishers  []RemovePublisherYAML  `yaml:"remove-publishers"`
	} `yaml:"target"`
	Dimensions struct {
		Technologies []string `yaml:"technologies"`
		Geopolitical []string `yaml:"geopolitical"`
		Sensitivity  []string `yaml:"sensitivity"`
		Users        []string `yaml:"users"`
		Groups       []string `yaml:"groups"`
	} `yaml:"dimensions"`
}

// ParseTargetRegistration parses a TargetRegistration YAML artifact.
func ParseTargetRegistration(data []byte) (*TargetRegistrationYAML, error) {
	var reg TargetRegistrationYAML
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse TargetRegistration YAML: %w", err)
	}
	if reg.Target.ID == "" {
		return nil, fmt.Errorf("missing target.id")
	}
	return &reg, nil
}

// ValidateTargetRegistration checks trusted-publishers and remove-publishers entries.
func ValidateTargetRegistration(reg *TargetRegistrationYAML) error {
	seen := make(map[string]bool)

	for i, p := range reg.Target.TrustedPublishers {
		if p.Issuer == "" {
			return fmt.Errorf("trusted-publishers[%d]: issuer is required", i)
		}
		if p.SubPattern == "" {
			return fmt.Errorf("trusted-publishers[%d]: sub_pattern is required", i)
		}
		seen[p.Issuer+"\x00"+p.SubPattern] = true
	}

	for i, p := range reg.Target.RemovePublishers {
		if p.Issuer == "" {
			return fmt.Errorf("remove-publishers[%d]: issuer is required", i)
		}
		if p.SubPattern == "" {
			return fmt.Errorf("remove-publishers[%d]: sub_pattern is required", i)
		}
		key := p.Issuer + "\x00" + p.SubPattern
		if seen[key] {
			return fmt.Errorf("remove-publishers[%d]: (%s, %s) conflicts with trusted-publishers", i, p.Issuer, p.SubPattern)
		}
	}

	return nil
}

// FlattenEvaluation parses and flattens an EvaluationLog artifact.
func FlattenEvaluation(ctx context.Context, data []byte) ([]EvidenceRow, string, error) {
	f := &bytesFetcher{data: data}
	evalLog, err := gemara.Load[gemara.EvaluationLog](ctx, f, "upload.yaml")
	if err != nil {
		return nil, "", fmt.Errorf("parse EvaluationLog: %w", err)
	}
	policyID := derivePolicyID(evalLog.Metadata.MappingReferences)
	rows, err := FlattenEvaluationLog(evalLog, policyID)
	return rows, policyID, err
}

// FlattenEnforcement parses and flattens an EnforcementLog artifact.
func FlattenEnforcement(ctx context.Context, data []byte) ([]EvidenceRow, string, error) {
	f := &bytesFetcher{data: data}
	enfLog, err := gemara.Load[gemara.EnforcementLog](ctx, f, "upload.yaml")
	if err != nil {
		return nil, "", fmt.Errorf("parse EnforcementLog: %w", err)
	}
	policyID := derivePolicyID(enfLog.Metadata.MappingReferences)
	rows, err := FlattenEnforcementLog(enfLog, policyID)
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
