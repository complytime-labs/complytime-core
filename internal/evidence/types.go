// SPDX-License-Identifier: Apache-2.0

package evidence

import "time"

// EvidenceRecord represents a single evidence row for the REST API.
// Fields align with evidence-semconv-alignment.md; new fields use omitempty
// for backward compatibility with minimal payloads.
type EvidenceRecord struct {
	EvidenceID string `json:"evidence_id"`
	PolicyID   string `json:"policy_id"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TargetEnv  string `json:"target_env,omitempty"`

	EngineName    string `json:"engine_name,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	RuleID        string `json:"rule_id"`
	RuleName      string `json:"rule_name,omitempty"`
	RuleURI       string `json:"rule_uri,omitempty"`

	EvalResult  string `json:"eval_result"`
	EvalMessage string `json:"eval_message,omitempty"`

	ControlID            string   `json:"control_id"`
	ControlCatalogID     string   `json:"control_catalog_id,omitempty"`
	ControlCategory      string   `json:"control_category,omitempty"`
	ControlApplicability []string `json:"control_applicability,omitempty"`
	RequirementID        string   `json:"requirement_id,omitempty"`
	PlanID               string   `json:"plan_id,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	StepsExecuted        int      `json:"steps_executed,omitempty"`
	ComplianceStatus     string   `json:"compliance_status,omitempty"`
	RiskLevel            string   `json:"risk_level,omitempty"`
	Frameworks           []string `json:"frameworks,omitempty"`
	Requirements         []string `json:"requirements,omitempty"`

	RemediationAction string `json:"remediation_action,omitempty"`
	RemediationStatus string `json:"remediation_status,omitempty"`
	RemediationDesc   string `json:"remediation_desc,omitempty"`
	ExceptionID       string `json:"exception_id,omitempty"`
	ExceptionActive   *bool  `json:"exception_active,omitempty"`

	AttestationRef string `json:"attestation_ref,omitempty"`
	SourceRegistry string `json:"source_registry,omitempty"`
	BlobRef        string `json:"blob_ref,omitempty"`

	Owner          string    `json:"owner,omitempty"`
	CollectedAt    time.Time `json:"collected_at"`
	Classification string    `json:"classification,omitempty"`
	LogIndex       *uint64   `json:"log_index,omitempty"` // Tessera transparency log position

	// Publisher identity from JWT verification
	PublisherIssuer string `json:"publisher_issuer,omitempty"` // JWT iss claim
	SubmittedBy     string `json:"submitted_by,omitempty"`     // JWT sub claim
	PublisherType   string `json:"publisher_type,omitempty"`   // pipeline, service, or unknown
}

// EvidenceFilter holds query parameters for evidence queries.
type EvidenceFilter struct {
	PolicyIDs     []string
	ControlID     string
	TargetName    string
	TargetType    string
	TargetEnv     string
	EngineVersion string
	Owner         string
	Start         time.Time
	End           time.Time
	Limit         int
	Offset        int
}

// CertificationRow represents a single certification verdict.
type CertificationRow struct {
	EvidenceID       string    `json:"evidence_id"`
	Certifier        string    `json:"certifier"`
	CertifierVersion string    `json:"certifier_version"`
	Result           string    `json:"result"`
	Reason           string    `json:"reason"`
	CertifiedAt      time.Time `json:"certified_at,omitempty"`
}

// EvidenceRowLite is a lightweight evidence projection for the certifier pipeline.
type EvidenceRowLite struct {
	EvidenceID       string    `json:"evidence_id"`
	TargetID         string    `json:"target_id"`
	RuleID           string    `json:"rule_id"`
	EvalResult       string    `json:"eval_result"`
	ComplianceStatus string    `json:"compliance_status"`
	EngineName       string    `json:"engine_name"`
	SourceRegistry   string    `json:"source_registry"`
	AttestationRef   string    `json:"attestation_ref"`
	CollectedAt      time.Time `json:"collected_at"`
}

// WitnessEvidenceRow contains publisher data for witness verification.
type WitnessEvidenceRow struct {
	EvidenceID      string
	PublisherIssuer string
	SubmittedBy     string
	PublisherType   string
}

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

	AttestationRef *string
	SourceRegistry *string
	BlobRef        *string

	Owner *string

	CollectedAt time.Time
	LogIndex    *uint64 // Tessera transparency log position (optional)
}

// StrPtr returns nil for empty strings, pointer otherwise.
func StrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Uint16Ptr returns nil for zero, pointer otherwise.
func Uint16Ptr(v uint16) *uint16 {
	if v == 0 {
		return nil
	}
	return &v
}
