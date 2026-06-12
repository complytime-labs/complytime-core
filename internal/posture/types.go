// SPDX-License-Identifier: Apache-2.0

package posture

import "time"

// RequirementFilter holds query parameters for requirement matrix and evidence APIs.
type RequirementFilter struct {
	PolicyID       string
	Start          time.Time
	End            time.Time
	ControlFamily  string
	Classification string
	Limit          int
	Offset         int
}

// RequirementRow is a single row in the requirement matrix.
type RequirementRow struct {
	CatalogID       string `json:"catalog_id"`
	ControlID       string `json:"control_id"`
	ControlTitle    string `json:"control_title"`
	RequirementID   string `json:"requirement_id"`
	RequirementText string `json:"requirement_text"`
	EvidenceCount   uint64 `json:"evidence_count"`
	LatestEvidence  string `json:"latest_evidence,omitempty"`
	Classification  string `json:"classification,omitempty"`
}

// RequirementEvidenceRow is an evidence row returned in requirement drill-down.
type RequirementEvidenceRow struct {
	EvidenceID     string `json:"evidence_id"`
	TargetID       string `json:"target_id"`
	TargetName     string `json:"target_name,omitempty"`
	RuleID         string `json:"rule_id"`
	EvalResult     string `json:"eval_result"`
	Classification string `json:"classification,omitempty"`
	AssessedAt     string `json:"assessed_at,omitempty"`
	CollectedAt    string `json:"collected_at"`
	SourceRegistry string `json:"source_registry,omitempty"`
}

// CoverageResult holds the requirement-level gap analysis for a policy.
type CoverageResult struct {
	PolicyID            string   `json:"policy_id"`
	TotalRequirements   int      `json:"total_requirements"`
	CoveredRequirements int      `json:"covered_requirements"`
	CoveragePct         float64  `json:"coverage_pct"`
	Covered             []string `json:"covered"`
	Gaps                []string `json:"gaps"`
	Stale               []string `json:"stale,omitempty"`
	Unaligned           []string `json:"unaligned,omitempty"`
}

// CoverageFilter holds query parameters for coverage analysis.
type CoverageFilter struct {
	PolicyID  string
	TargetID  string
	Since     time.Time
	MaxAge    time.Duration
	Freshness map[string]time.Duration
}

// InventoryItem is a per-target rollup of latest eval status per policy.
type InventoryItem struct {
	TargetID       string    `json:"target_id"`
	TargetType     string    `json:"target_type"`
	Environment    string    `json:"environment"`
	PolicyCount    int       `json:"policy_count"`
	PassCount      int       `json:"pass_count"`
	FailCount      int       `json:"fail_count"`
	LatestEvidence time.Time `json:"latest_evidence"`
}

// InventoryFilter holds optional query params for ListInventory.
type InventoryFilter struct {
	PolicyID    string `query:"policy_id"`
	ProgramID   string `query:"program_id"`
	TargetType  string `query:"target_type"`
	Environment string `query:"environment"`
}
