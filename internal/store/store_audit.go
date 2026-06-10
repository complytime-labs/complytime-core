// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/audit"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/google/uuid"
)

// InsertAuditLog stores an AuditLog artifact.
func (s *Store) InsertAuditLog(ctx context.Context, a AuditLog) error {
	if a.AuditID == "" {
		a.AuditID = uuid.New().String()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (audit_id, policy_id, audit_start, audit_end, framework, created_by, content, summary, model, prompt_version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.AuditID, a.PolicyID, a.AuditStart, a.AuditEnd, a.Framework, a.CreatedBy, a.Content, a.Summary, a.Model, a.PromptVersion,
	)
	return err
}

// ListAuditLogs returns audit logs for a given policy, optionally filtered by time range.
func (s *Store) ListAuditLogs(ctx context.Context, policyID string, start, end time.Time, limit int) ([]AuditLog, error) {
	qb := psql.Select("audit_id", "policy_id", "audit_start", "audit_end", "framework",
		"created_at", "created_by", "summary", "model", "prompt_version").
		From("audit_logs").
		Where(sq.Eq{"policy_id": policyID}).
		OrderBy("audit_start DESC").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if !start.IsZero() {
		qb = qb.Where(sq.GtOrEq{"audit_start": start})
	}
	if !end.IsZero() {
		qb = qb.Where(sq.LtOrEq{"audit_end": end})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list audit logs: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.AuditID, &a.PolicyID, &a.AuditStart, &a.AuditEnd, &a.Framework, &a.CreatedAt, &a.CreatedBy, &a.Summary, &a.Model, &a.PromptVersion); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAuditLog returns a single audit log with full content.
func (s *Store) GetAuditLog(ctx context.Context, auditID string) (*AuditLog, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT audit_id, policy_id, audit_start, audit_end, framework, created_at, created_by, content, summary, model, prompt_version FROM audit_logs WHERE audit_id = $1`, auditID)
	var a AuditLog
	if err := row.Scan(&a.AuditID, &a.PolicyID, &a.AuditStart, &a.AuditEnd, &a.Framework, &a.CreatedAt, &a.CreatedBy, &a.Content, &a.Summary, &a.Model, &a.PromptVersion); err != nil {
		return nil, fmt.Errorf("get audit log: %w", err)
	}
	return &a, nil
}

// InsertEvidenceAssessments batch-inserts agent classifications.
func (s *Store) InsertEvidenceAssessments(ctx context.Context, assessments []EvidenceAssessment) error {
	if len(assessments) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin evidence assessments tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO evidence_assessments (evidence_id, policy_id, plan_id, classification, reason, assessed_at, assessed_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	for _, a := range assessments {
		if _, err := tx.Exec(ctx, q, a.EvidenceID, a.PolicyID, a.PlanID, a.Classification, a.Reason, a.AssessedAt, a.AssessedBy); err != nil {
			return fmt.Errorf("insert evidence assessment: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit evidence assessments: %w", err)
	}
	return nil
}

// InsertDraftAuditLog stores an agent-produced draft.
func (s *Store) InsertDraftAuditLog(ctx context.Context, d DraftAuditLog) error {
	if d.DraftID == "" {
		d.DraftID = uuid.New().String()
	}
	if d.Status == "" {
		d.Status = "pending_review"
	}
	edits := d.ReviewerEdits
	if edits == "" {
		edits = "{}"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO draft_audit_logs (draft_id, policy_id, audit_start, audit_end, framework, status, content, summary, agent_reasoning, model, prompt_version, reviewer_edits) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		d.DraftID, d.PolicyID, d.AuditStart, d.AuditEnd, d.Framework, d.Status, d.Content, d.Summary, d.AgentReasoning, d.Model, d.PromptVersion, edits,
	)
	return err
}

// ListDraftAuditLogs returns drafts filtered by status. Empty status returns all.
func (s *Store) ListDraftAuditLogs(ctx context.Context, status string, limit int) ([]DraftAuditLog, error) {
	qb := psql.Select("draft_id", "policy_id", "audit_start", "audit_end", "framework",
		"created_at", "status", "summary", "agent_reasoning", "model", "prompt_version",
		"reviewed_by", "promoted_at", "reviewer_edits").
		From("draft_audit_logs").
		OrderBy("created_at DESC").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if status != "" {
		qb = qb.Where(sq.Eq{"status": status})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list draft audit logs: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list draft audit logs: %w", err)
	}
	defer rows.Close()

	var out []DraftAuditLog
	for rows.Next() {
		var d DraftAuditLog
		if err := rows.Scan(&d.DraftID, &d.PolicyID, &d.AuditStart, &d.AuditEnd, &d.Framework, &d.CreatedAt, &d.Status, &d.Summary, &d.AgentReasoning, &d.Model, &d.PromptVersion, &d.ReviewedBy, &d.PromotedAt, &d.ReviewerEdits); err != nil {
			return nil, fmt.Errorf("scan draft audit log: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDraftAuditLog returns a single draft with full content.
func (s *Store) GetDraftAuditLog(ctx context.Context, draftID string) (*DraftAuditLog, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT draft_id, policy_id, audit_start, audit_end, framework, created_at, status, content, summary, agent_reasoning, model, prompt_version, reviewed_by, promoted_at, reviewer_edits FROM draft_audit_logs WHERE draft_id = $1`, draftID)
	var d DraftAuditLog
	if err := row.Scan(&d.DraftID, &d.PolicyID, &d.AuditStart, &d.AuditEnd, &d.Framework, &d.CreatedAt, &d.Status, &d.Content, &d.Summary, &d.AgentReasoning, &d.Model, &d.PromptVersion, &d.ReviewedBy, &d.PromotedAt, &d.ReviewerEdits); err != nil {
		return nil, fmt.Errorf("get draft audit log: %w", err)
	}
	return &d, nil
}

// UpdateDraftEdits persists reviewer edits (type overrides, notes) on a pending draft.
func (s *Store) UpdateDraftEdits(ctx context.Context, draftID string, reviewerEdits string) error {
	draft, err := s.GetDraftAuditLog(ctx, draftID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, draftID)
	}
	if draft.Status != "pending_review" {
		return ErrDraftAlreadyPromoted
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE draft_audit_logs SET reviewer_edits = $1 WHERE draft_id = $2 AND status = 'pending_review'`,
		reviewerEdits, draftID)
	return err
}

// PromoteDraftAuditLog copies a draft to the official audit_logs table and marks it promoted.
func (s *Store) PromoteDraftAuditLog(ctx context.Context, draftID string, reviewedBy string) error {
	draft, err := s.GetDraftAuditLog(ctx, draftID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, draftID)
	}
	if draft.Status == "promoted" {
		return ErrDraftAlreadyPromoted
	}

	mergedContent, err := audit.MergeReviewerEdits(draft.Content, draft.ReviewerEdits)
	if err != nil {
		slog.Warn("reviewer edits merge failed, using original content", "draft_id", draftID, "error", err)
		mergedContent = draft.Content
	}

	official := AuditLog{
		AuditID:       uuid.New().String(),
		PolicyID:      draft.PolicyID,
		AuditStart:    draft.AuditStart,
		AuditEnd:      draft.AuditEnd,
		Framework:     draft.Framework,
		CreatedBy:     reviewedBy,
		Content:       mergedContent,
		Summary:       draft.Summary,
		Model:         draft.Model,
		PromptVersion: draft.PromptVersion,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin promote draft: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_logs (audit_id, policy_id, audit_start, audit_end, framework, created_by, content, summary, model, prompt_version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		official.AuditID, official.PolicyID, official.AuditStart, official.AuditEnd, official.Framework, official.CreatedBy, official.Content, official.Summary, official.Model, official.PromptVersion,
	); err != nil {
		return fmt.Errorf("insert promoted audit log: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE draft_audit_logs SET status = $1, reviewed_by = $2, promoted_at = now() WHERE draft_id = $3`,
		"promoted", reviewedBy, draft.DraftID,
	); err != nil {
		return fmt.Errorf("mark draft promoted: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit promote draft: %w", err)
	}
	return nil
}
