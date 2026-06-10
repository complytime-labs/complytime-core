// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"time"
)

// AuditLogStore defines read/write operations for audit log artifacts.
type AuditLogStore interface {
	InsertAuditLog(ctx context.Context, a AuditLog) error
	ListAuditLogs(ctx context.Context, policyID string, start, end time.Time, limit int) ([]AuditLog, error)
	GetAuditLog(ctx context.Context, auditID string) (*AuditLog, error)
}

// EvidenceAssessmentStore defines write operations for agent-produced classifications.
type EvidenceAssessmentStore interface {
	InsertEvidenceAssessments(ctx context.Context, assessments []EvidenceAssessment) error
}

// DraftAuditLogStore defines operations for agent-produced draft audit logs
// that require human review before promotion to the official audit_logs table.
type DraftAuditLogStore interface {
	InsertDraftAuditLog(ctx context.Context, d DraftAuditLog) error
	ListDraftAuditLogs(ctx context.Context, status string, limit int) ([]DraftAuditLog, error)
	GetDraftAuditLog(ctx context.Context, draftID string) (*DraftAuditLog, error)
	UpdateDraftEdits(ctx context.Context, draftID string, reviewerEdits string) error
	PromoteDraftAuditLog(ctx context.Context, draftID string, reviewedBy string) error
}
