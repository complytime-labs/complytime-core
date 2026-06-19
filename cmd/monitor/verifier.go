// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
)

type TesseraReader interface {
	Read(ctx context.Context, index uint64) ([]byte, error)
	ReadCheckpoint(ctx context.Context) ([]byte, error)
}

type PostgresQuerier interface {
	QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*EvidenceRow, error)
	IsIndexWitnessed(ctx context.Context, index uint64) bool
	IsTargetRegistered(ctx context.Context, targetID string) bool
	PolicyExistsByID(ctx context.Context, policyID string) bool
	HasFailedTrustSignals(ctx context.Context, evidenceID string) (bool, error)
}

type EvidenceRow struct {
	EvidenceID      string
	PublisherIssuer string
	SubmittedBy     string
}

type Verifier struct {
	tessera TesseraReader
	db      PostgresQuerier
	config  *Config
}

func NewVerifier(tessera TesseraReader, db PostgresQuerier, config *Config) *Verifier {
	return &Verifier{
		tessera: tessera,
		db:      db,
		config:  config,
	}
}

func (v *Verifier) VerifyEntry(ctx context.Context, logIndex uint64) bool {
	// 1. Fetch entry from Tessera
	entry, err := v.tessera.Read(ctx, logIndex)
	if err != nil {
		slog.Error("failed to read entry from Tessera", "log_index", logIndex, "error", err)
		return false
	}

	// 2. Parse Gemara artifact type
	artifactType, err := parseGemaraType(entry)
	if err != nil {
		// Entry exists in Tessera but isn't a valid Gemara artifact.
		// This could be a TargetRegistration (no metadata.type) — try parsing as one.
		if targetID, _ := parseTargetRegistrationID(entry); targetID != "" {
			return v.verifyTargetRegistration(ctx, logIndex, entry, targetID)
		}
		slog.Error("invalid Gemara artifact", "log_index", logIndex, "error", err)
		return false
	}

	// 3. Route verification by artifact type
	switch artifactType {
	case "EvaluationLog", "EnforcementLog":
		return v.verifyEvidence(ctx, logIndex, entry, artifactType)
	case "AuditLog":
		return v.verifyAuditLog(ctx, logIndex, entry)
	case "Policy":
		return v.verifyPolicy(ctx, logIndex, entry)
	default:
		// Catalogs and other types: existence proof is sufficient
		slog.Info("verified entry by existence (non-evidence type)",
			"log_index", logIndex, "type", artifactType)
		return true
	}
}

// verifyEvidence runs the full verification pipeline for EvaluationLog/EnforcementLog.
func (v *Verifier) verifyEvidence(ctx context.Context, logIndex uint64, entry []byte, artifactType string) bool {
	evidenceRow, err := v.db.QueryEvidenceByLogIndex(ctx, logIndex)
	if err != nil {
		slog.Warn("evidence not yet in PostgreSQL", "log_index", logIndex, "error", err)
		return false
	}
	if evidenceRow == nil {
		slog.Warn("evidence not yet in PostgreSQL", "log_index", logIndex)
		return false
	}

	// Check trust signals - evidence fails if any signal is fail/error
	hasFailed, err := v.db.HasFailedTrustSignals(ctx, evidenceRow.EvidenceID)
	if err != nil {
		slog.Warn("trust signal query failed", "log_index", logIndex, "error", err)
		return false
	}
	if hasFailed {
		slog.Warn("evidence has failed trust signals", "log_index", logIndex, "evidence_id", evidenceRow.EvidenceID)
		return false
	}

	if !v.isPublisherTrusted(evidenceRow.PublisherIssuer, evidenceRow.SubmittedBy, artifactType) {
		slog.Warn("publisher not trusted",
			"log_index", logIndex,
			"issuer", evidenceRow.PublisherIssuer,
			"sub", evidenceRow.SubmittedBy)
		return false
	}

	// Advisory: check target registration (non-blocking)
	targetID, _ := parseTarget(entry)
	if targetID != "" && !v.db.IsTargetRegistered(ctx, targetID) {
		slog.Warn("evidence references unregistered target (advisory)",
			"log_index", logIndex, "target_id", targetID)
	}

	// Verify policy reference integrity
	policyRefs, err := extractPolicyReferences(entry)
	if err != nil {
		slog.Error("failed to parse policy references", "log_index", logIndex, "error", err)
		return false
	}
	for _, policyIndex := range policyRefs {
		if !v.verifyPolicyReference(ctx, policyIndex) {
			slog.Warn("policy reference not found or not witnessed",
				"log_index", logIndex, "policy_log_index", policyIndex)
			return false
		}
	}

	return true
}

// verifyAuditLog extends evidence verification with evidence-reference and target-scoping checks.
func (v *Verifier) verifyAuditLog(ctx context.Context, logIndex uint64, entry []byte) bool {
	if !v.verifyEvidence(ctx, logIndex, entry, "AuditLog") {
		return false
	}

	evidenceRefs, err := extractEvidenceReferences(entry)
	if err != nil {
		slog.Error("failed to parse evidence references", "log_index", logIndex, "error", err)
		return false
	}
	for _, evidenceIndex := range evidenceRefs {
		if !v.verifyEvidenceReference(ctx, evidenceIndex) {
			slog.Warn("evidence reference not found or not witnessed",
				"log_index", logIndex, "evidence_log_index", evidenceIndex)
			return false
		}
	}
	if len(evidenceRefs) > 0 && !v.verifyTargetScoping(ctx, entry, evidenceRefs) {
		slog.Warn("AuditLog references evidence from multiple targets", "log_index", logIndex)
		return false
	}

	return true
}

// verifyPolicy checks that a Policy artifact was processed by the ingest worker.
func (v *Verifier) verifyPolicy(ctx context.Context, logIndex uint64, entry []byte) bool {
	policyID := parsePolicyID(entry)
	if policyID == "" {
		slog.Warn("policy has no metadata.id", "log_index", logIndex)
		return false
	}
	if !v.db.PolicyExistsByID(ctx, policyID) {
		slog.Warn("policy not yet in PostgreSQL", "log_index", logIndex, "policy_id", policyID)
		return false
	}
	slog.Info("verified policy entry", "log_index", logIndex, "policy_id", policyID)
	return true
}

// verifyTargetRegistration checks that a TargetRegistration was processed.
func (v *Verifier) verifyTargetRegistration(ctx context.Context, logIndex uint64, _ []byte, targetID string) bool {
	if !v.db.IsTargetRegistered(ctx, targetID) {
		slog.Warn("target not yet registered in PostgreSQL", "log_index", logIndex, "target_id", targetID)
		return false
	}
	slog.Info("verified target registration entry", "log_index", logIndex, "target_id", targetID)
	return true
}

func (v *Verifier) isPublisherTrusted(issuer, sub, artifactType string) bool {
	for _, pub := range v.config.TrustedPublishers {
		// Check issuer matches
		if pub.Issuer != issuer {
			continue
		}

		// Check sub matches (glob pattern)
		if !globMatch(pub.Sub, sub) {
			continue
		}

		// Check artifact type allowed
		for _, allowedType := range pub.AllowedTypes {
			if allowedType == artifactType {
				return true
			}
		}
	}

	return false
}

// globMatch performs simple glob pattern matching where * matches any sequence of characters
// This differs from filepath.Match in that * matches across path separators
func globMatch(pattern, text string) bool {
	// Handle exact match
	if pattern == text {
		return true
	}

	// Handle patterns ending with * (most common case for publisher sub patterns)
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(text, prefix)
	}

	// For other patterns, exact match only
	return false
}

func (v *Verifier) verifyPolicyReference(ctx context.Context, policyIndex uint64) bool {
	// Verify policy exists at claimed log_index
	policyEntry, err := v.tessera.Read(ctx, policyIndex)
	if err != nil {
		return false
	}

	// Verify it's actually a Policy artifact
	artifactType, err := parseGemaraType(policyEntry)
	if err != nil || artifactType != "Policy" {
		return false
	}

	// Verify policy is witnessed
	return v.isIndexWitnessed(ctx, policyIndex)
}

func (v *Verifier) verifyEvidenceReference(ctx context.Context, evidenceIndex uint64) bool {
	// Verify evidence exists
	evidenceEntry, err := v.tessera.Read(ctx, evidenceIndex)
	if err != nil {
		return false
	}

	// Verify it's an EvaluationLog or EnforcementLog
	artifactType, err := parseGemaraType(evidenceEntry)
	if err != nil {
		return false
	}
	if artifactType != "EvaluationLog" && artifactType != "EnforcementLog" {
		return false
	}

	// Verify evidence is witnessed
	return v.isIndexWitnessed(ctx, evidenceIndex)
}

func (v *Verifier) verifyTargetScoping(ctx context.Context, auditLog []byte, evidenceRefs []uint64) bool {
	// Parse target from AuditLog
	auditTarget, err := parseTarget(auditLog)
	if err != nil {
		return false
	}

	// Verify all referenced evidence is for the same target
	for _, evidenceIndex := range evidenceRefs {
		evidenceEntry, err := v.tessera.Read(ctx, evidenceIndex)
		if err != nil {
			return false
		}
		evidenceTarget, err := parseTarget(evidenceEntry)
		if err != nil {
			return false
		}
		if evidenceTarget != auditTarget {
			return false
		}
	}

	return true
}

func (v *Verifier) isIndexWitnessed(ctx context.Context, index uint64) bool {
	// Query witness state: has this index been cosigned?
	return v.db.IsIndexWitnessed(ctx, index)
}

func extractPolicyReferences(entry []byte) ([]uint64, error) {
	var doc struct {
		Metadata struct {
			MappingReferences []struct {
				ID              string `yaml:"id"`
				TesseraLogIndex uint64 `yaml:"tessera-log-index"`
			} `yaml:"mapping-references"`
		} `yaml:"metadata"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return nil, err
	}

	var indices []uint64
	for _, ref := range doc.Metadata.MappingReferences {
		// Include all indices, including 0 (valid index in log)
		indices = append(indices, ref.TesseraLogIndex)
	}

	return indices, nil
}

func extractEvidenceReferences(entry []byte) ([]uint64, error) {
	var doc struct {
		Results []struct {
			Evidence []struct {
				TesseraLogIndex uint64 `yaml:"tessera-log-index"`
			} `yaml:"evidence"`
		} `yaml:"results"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return nil, err
	}

	var indices []uint64
	for _, result := range doc.Results {
		for _, evidence := range result.Evidence {
			// Include all indices, including 0 (valid index in log)
			indices = append(indices, evidence.TesseraLogIndex)
		}
	}

	return indices, nil
}

func parseTarget(entry []byte) (string, error) {
	var doc struct {
		Target struct {
			ID string `yaml:"id"`
		} `yaml:"target"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return "", err
	}

	if doc.Target.ID == "" {
		return "", fmt.Errorf("missing target.id")
	}

	return doc.Target.ID, nil
}

func parsePolicyID(entry []byte) string {
	var doc struct {
		Metadata struct {
			ID string `yaml:"id"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return ""
	}
	return doc.Metadata.ID
}

// parseTargetRegistrationID attempts to parse entry as a TargetRegistration
// (which lacks metadata.type but has target.id and target.technologies).
func parseTargetRegistrationID(entry []byte) (string, error) {
	var doc struct {
		Target struct {
			ID           string   `yaml:"id"`
			Technologies []string `yaml:"technologies"`
		} `yaml:"target"`
	}
	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return "", err
	}
	if doc.Target.ID == "" || len(doc.Target.Technologies) == 0 {
		return "", fmt.Errorf("not a TargetRegistration")
	}
	return doc.Target.ID, nil
}

func parseGemaraType(entry []byte) (string, error) {
	var metadata struct {
		Metadata struct {
			Type string `yaml:"type"`
		} `yaml:"metadata"`
	}

	if err := yaml.Unmarshal(entry, &metadata); err != nil {
		return "", fmt.Errorf("parse YAML: %w", err)
	}

	if metadata.Metadata.Type == "" {
		return "", fmt.Errorf("missing metadata.type")
	}

	return metadata.Metadata.Type, nil
}
