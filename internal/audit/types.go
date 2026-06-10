// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"time"
)

// AuditLog represents a stored audit log artifact.
type AuditLog struct {
	AuditID       string    `json:"audit_id"`
	PolicyID      string    `json:"policy_id"`
	AuditStart    time.Time `json:"audit_start"`
	AuditEnd      time.Time `json:"audit_end"`
	Framework     string    `json:"framework,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
	Content       string    `json:"content"`
	Summary       string    `json:"summary"`
	Model         string    `json:"model,omitempty"`
	PromptVersion string    `json:"prompt_version,omitempty"`
}

// DraftAuditLog represents an agent-produced audit log awaiting human review.
type DraftAuditLog struct {
	DraftID        string     `json:"draft_id"`
	PolicyID       string     `json:"policy_id"`
	AuditStart     time.Time  `json:"audit_start"`
	AuditEnd       time.Time  `json:"audit_end"`
	Framework      string     `json:"framework,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	Status         string     `json:"status"`
	Content        string     `json:"content"`
	Summary        string     `json:"summary"`
	AgentReasoning string     `json:"agent_reasoning,omitempty"`
	Model          string     `json:"model,omitempty"`
	PromptVersion  string     `json:"prompt_version,omitempty"`
	ReviewedBy     *string    `json:"reviewed_by,omitempty"`
	PromotedAt     *time.Time `json:"promoted_at,omitempty"`
	ReviewerEdits  string     `json:"reviewer_edits,omitempty"`
}

// EvidenceAssessment represents an agent-produced classification for an evidence row.
type EvidenceAssessment struct {
	EvidenceID     string    `json:"evidence_id"`
	PolicyID       string    `json:"policy_id"`
	PlanID         string    `json:"plan_id"`
	Classification string    `json:"classification"`
	Reason         string    `json:"reason"`
	AssessedAt     time.Time `json:"assessed_at"`
	AssessedBy     string    `json:"assessed_by"`
}

// ErrRequirementNotFound is returned by ListRequirementEvidence when the
// requirement ID is not known for the policy.
var ErrRequirementNotFound = errors.New("requirement not found")

// ErrDraftAlreadyPromoted is returned when a draft has already been promoted.
var ErrDraftAlreadyPromoted = errors.New("draft already promoted")

// ErrDraftNotFound is returned when a draft is not found.
var ErrDraftNotFound = errors.New("draft not found")

// ValidClassifications enumerates the allowed 7-state classification values.
var ValidClassifications = map[string]bool{
	"Healthy":        true,
	"Failing":        true,
	"Wrong Source":   true,
	"Wrong Method":   true,
	"Unfit Evidence": true,
	"Stale":          true,
	"No Evidence":    true,
}
