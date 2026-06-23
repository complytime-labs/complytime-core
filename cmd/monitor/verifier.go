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

type Verifier struct {
	tessera TesseraReader
	config  *Config
}

func NewVerifier(tessera TesseraReader, config *Config) *Verifier {
	return &Verifier{
		tessera: tessera,
		config:  config,
	}
}

func (v *Verifier) VerifyEntry(ctx context.Context, logIndex uint64) bool {
	entry, err := v.tessera.Read(ctx, logIndex)
	if err != nil {
		slog.Error("failed to read entry from Tessera", "log_index", logIndex, "error", err)
		return false
	}

	artifactType, err := parseGemaraType(entry)
	if err != nil {
		if targetID, _ := parseTargetRegistrationID(entry); targetID != "" {
			slog.Info("verified target registration entry", "log_index", logIndex, "target_id", targetID)
			return true
		}
		slog.Error("invalid Gemara artifact", "log_index", logIndex, "error", err)
		return false
	}

	switch artifactType {
	case "EvaluationLog", "EnforcementLog":
		return v.verifyEvidence(ctx, logIndex, entry, artifactType)
	case "AuditLog":
		return v.verifyAuditLog(ctx, logIndex, entry)
	case "Policy":
		return v.verifyPolicy(logIndex, entry)
	default:
		slog.Info("verified entry by existence (non-evidence type)",
			"log_index", logIndex, "type", artifactType)
		return true
	}
}

func (v *Verifier) verifyEvidence(ctx context.Context, logIndex uint64, entry []byte, artifactType string) bool {
	publisher := parsePublisher(entry)
	if !v.isPublisherTrusted(publisher.Issuer, publisher.Sub, artifactType) {
		slog.Warn("publisher not trusted",
			"log_index", logIndex,
			"issuer", publisher.Issuer,
			"sub", publisher.Sub)
		return false
	}

	policyRefs, err := extractPolicyReferences(entry)
	if err != nil {
		slog.Error("failed to parse policy references", "log_index", logIndex, "error", err)
		return false
	}
	for _, policyIndex := range policyRefs {
		if !v.verifyPolicyReference(ctx, policyIndex) {
			slog.Warn("policy reference not found",
				"log_index", logIndex, "policy_log_index", policyIndex)
			return false
		}
	}

	slog.Info("verified evidence entry", "log_index", logIndex, "type", artifactType)
	return true
}

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
			slog.Warn("evidence reference not found",
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

func (v *Verifier) verifyPolicy(logIndex uint64, entry []byte) bool {
	policyID := parsePolicyID(entry)
	if policyID == "" {
		slog.Warn("policy has no metadata.id", "log_index", logIndex)
		return false
	}
	slog.Info("verified policy entry", "log_index", logIndex, "policy_id", policyID)
	return true
}

func (v *Verifier) isPublisherTrusted(issuer, sub, artifactType string) bool {
	for _, pub := range v.config.TrustedPublishers {
		if pub.Issuer != issuer {
			continue
		}
		if !globMatch(pub.Sub, sub) {
			continue
		}
		for _, allowedType := range pub.AllowedTypes {
			if allowedType == artifactType {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, text string) bool {
	if pattern == text {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(text, prefix)
	}
	return false
}

func (v *Verifier) verifyPolicyReference(ctx context.Context, policyIndex uint64) bool {
	policyEntry, err := v.tessera.Read(ctx, policyIndex)
	if err != nil {
		return false
	}
	artifactType, err := parseGemaraType(policyEntry)
	return err == nil && artifactType == "Policy"
}

func (v *Verifier) verifyEvidenceReference(ctx context.Context, evidenceIndex uint64) bool {
	evidenceEntry, err := v.tessera.Read(ctx, evidenceIndex)
	if err != nil {
		return false
	}
	artifactType, err := parseGemaraType(evidenceEntry)
	if err != nil {
		return false
	}
	return artifactType == "EvaluationLog" || artifactType == "EnforcementLog"
}

func (v *Verifier) verifyTargetScoping(ctx context.Context, auditLog []byte, evidenceRefs []uint64) bool {
	auditTarget, err := parseTarget(auditLog)
	if err != nil {
		return false
	}
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

type publisherInfo struct {
	Issuer string
	Sub    string
}

func parsePublisher(entry []byte) publisherInfo {
	var doc struct {
		Publisher struct {
			Issuer string `yaml:"issuer"`
			Sub    string `yaml:"sub"`
		} `yaml:"publisher"`
	}
	_ = yaml.Unmarshal(entry, &doc)
	return publisherInfo{Issuer: doc.Publisher.Issuer, Sub: doc.Publisher.Sub}
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
