// SPDX-License-Identifier: Apache-2.0

package ingest

import "time"

// EvidenceRow is a flattened row for the unified `evidence` PostgreSQL table.
// Co-locates evaluation and remediation data; remediation fields are nil
// for evaluation-only records.
type EvidenceRow struct {
	EvidenceID string

	TargetID   string
	TargetName *string
	TargetType *string
	TargetEnv  *string

	EngineName    *string
	EngineVersion *string
	RuleID        string
	RuleName      *string
	RuleURI       *string

	EvalResult  string
	EvalMessage *string

	PolicyID             *string
	ControlID            *string
	ControlCatalogID     *string
	ControlCategory      *string
	ControlApplicability []string
	RequirementID        *string
	PlanID               *string
	Confidence           *string
	StepsExecuted        *uint16
	ComplianceStatus     string
	RiskLevel            *string
	Frameworks           []string
	Requirements         []string

	RemediationAction *string
	RemediationStatus *string
	RemediationDesc   *string
	ExceptionID       *string
	ExceptionActive   *bool

	EnrichmentStatus string

	AttestationRef *string
	SourceRegistry *string
	BlobRef        *string

	Owner     *string

	CollectedAt time.Time
	LogIndex    *uint64 // Tessera transparency log position (optional)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func uint16Ptr(v uint16) *uint16 {
	if v == 0 {
		return nil
	}
	return &v
}
