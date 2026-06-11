// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// nullStr returns nil for empty strings, pointer otherwise.
func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nullUint16 returns nil for zero, pointer otherwise.
func nullUint16(v int) *uint16 {
	if v <= 0 {
		return nil
	}
	u := uint16(v) //nolint:gosec // G115: DB value
	return &u
}

// warnEvalMessageIfLarge logs when eval_message may be raw or embedded data
// rather than a short summary (see consts.EvalMessageWarnBytes).
func warnEvalMessageIfLarge(r evidence.EvidenceRecord) {
	if len(r.EvalMessage) <= consts.EvalMessageWarnBytes {
		return
	}
	slog.Warn("evidence eval_message exceeds recommended summary size",
		"bytes", len(r.EvalMessage),
		"warn_threshold_bytes", consts.EvalMessageWarnBytes,
		"policy_id", r.PolicyID,
		"evidence_id", r.EvidenceID,
	)
}

// normalizeEvidence applies defaults to an EvidenceRecord before insert.
func normalizeEvidence(r *evidence.EvidenceRecord) {
	if r.EvidenceID == "" {
		r.EvidenceID = uuid.New().String()
	}
	if r.ComplianceStatus == "" {
		r.ComplianceStatus = "Unknown"
	}
	if r.EvalResult == "" {
		r.EvalResult = "Unknown"
	}
	if r.ControlApplicability == nil {
		r.ControlApplicability = []string{}
	}
	if r.Requirements == nil {
		r.Requirements = []string{}
	}
}

// InsertEvidence batch-inserts evidence records with full semconv column coverage.
func (s *Store) InsertEvidence(ctx context.Context, records []evidence.EvidenceRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin evidence tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO evidence (
		evidence_id, target_id, target_name, target_type, target_env,
		engine_name, engine_version, rule_id, rule_name, rule_uri,
		eval_result, eval_message,
		policy_id, control_id, control_catalog_id, control_category,
		control_applicability, requirement_id, plan_id,
		confidence, steps_executed, compliance_status,
		risk_level, requirements,
		remediation_action, remediation_status, remediation_desc,
		exception_id, exception_active,
		attestation_ref, source_registry, blob_ref,
		owner, collected_at, log_index,
		publisher_issuer, submitted_by, publisher_type
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)
	ON CONFLICT (evidence_id, control_id, requirement_id) DO UPDATE SET
		target_name = EXCLUDED.target_name,
		target_type = EXCLUDED.target_type,
		target_env = EXCLUDED.target_env,
		engine_name = EXCLUDED.engine_name,
		engine_version = EXCLUDED.engine_version,
		eval_result = EXCLUDED.eval_result,
		eval_message = EXCLUDED.eval_message,
		compliance_status = EXCLUDED.compliance_status,
		owner = EXCLUDED.owner,
		collected_at = EXCLUDED.collected_at,
		log_index = EXCLUDED.log_index,
		publisher_issuer = EXCLUDED.publisher_issuer,
		submitted_by = EXCLUDED.submitted_by,
		publisher_type = EXCLUDED.publisher_type`

	count := 0
	for _, r := range records {
		normalizeEvidence(&r)
		warnEvalMessageIfLarge(r)
		if _, err := tx.Exec(ctx, q,
			r.EvidenceID,
			r.TargetID, nullStr(r.TargetName), nullStr(r.TargetType), nullStr(r.TargetEnv),
			nullStr(r.EngineName), nullStr(r.EngineVersion), r.RuleID, nullStr(r.RuleName), nullStr(r.RuleURI),
			r.EvalResult, nullStr(r.EvalMessage),
			r.PolicyID, r.ControlID, nullStr(r.ControlCatalogID), nullStr(r.ControlCategory),
			r.ControlApplicability, r.RequirementID, nullStr(r.PlanID),
			nullStr(r.Confidence), nullUint16(r.StepsExecuted), r.ComplianceStatus,
			nullStr(r.RiskLevel), r.Requirements,
			nullStr(r.RemediationAction), nullStr(r.RemediationStatus), nullStr(r.RemediationDesc),
			nullStr(r.ExceptionID), r.ExceptionActive,
			nullStr(r.AttestationRef), nullStr(r.SourceRegistry), nullStr(r.BlobRef),
			nullStr(r.Owner), r.CollectedAt, r.LogIndex,
			nullStr(r.PublisherIssuer), nullStr(r.SubmittedBy), nullStr(r.PublisherType),
		); err != nil {
			return count, fmt.Errorf("insert evidence row: %w", err)
		}
		count++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit evidence: %w", err)
	}
	return count, nil
}

// QueryEvidence returns evidence rows matching the filter.
func (s *Store) QueryEvidence(ctx context.Context, f evidence.EvidenceFilter) ([]evidence.EvidenceRecord, error) {
	qb := psql.Select(
		"e.evidence_id", "e.policy_id", "e.target_id",
		"COALESCE(e.target_name, '') AS target_name",
		"COALESCE(e.target_type, '') AS target_type",
		"COALESCE(e.target_env, '') AS target_env",
		"COALESCE(e.engine_name, '') AS engine_name",
		"COALESCE(e.engine_version, '') AS engine_version",
		"e.rule_id",
		"COALESCE(e.rule_name, '') AS rule_name",
		"e.eval_result",
		"COALESCE(e.eval_message, '') AS eval_message",
		"e.control_id",
		"COALESCE(e.control_catalog_id, '') AS control_catalog_id",
		"COALESCE(e.control_category, '') AS control_category",
		"e.requirement_id",
		"COALESCE(e.plan_id, '') AS plan_id",
		"COALESCE(e.confidence, '') AS confidence",
		"e.compliance_status",
		"COALESCE(e.risk_level, '') AS risk_level",
		"e.requirements",
		"COALESCE(e.attestation_ref, '') AS attestation_ref",
		"COALESCE(e.source_registry, '') AS source_registry",
		"COALESCE(e.blob_ref, '') AS blob_ref",
		"e.collected_at",
		"e.log_index",
		"COALESCE(ea_latest.classification, '') AS classification",
	).From(`evidence e
		LEFT JOIN LATERAL (
			SELECT ea2.classification
			FROM evidence_assessments ea2
			WHERE ea2.evidence_id = e.evidence_id
			ORDER BY ea2.assessed_at DESC
			LIMIT 1
		) AS ea_latest ON TRUE`).
		OrderBy("e.collected_at DESC")

	if len(f.PolicyIDs) == 1 {
		qb = qb.Where(sq.Eq{"e.policy_id": f.PolicyIDs[0]})
	} else if len(f.PolicyIDs) > 1 {
		qb = qb.Where(sq.Eq{"e.policy_id": f.PolicyIDs})
	}
	if f.ControlID != "" {
		qb = qb.Where(sq.Eq{"e.control_id": f.ControlID})
	}
	if f.TargetName != "" {
		qb = qb.Where(sq.Eq{"e.target_name": f.TargetName})
	}
	if f.TargetType != "" {
		qb = qb.Where(sq.Eq{"e.target_type": f.TargetType})
	}
	if f.TargetEnv != "" {
		qb = qb.Where(sq.Eq{"e.target_env": f.TargetEnv})
	}
	if f.EngineVersion != "" {
		qb = qb.Where(sq.Eq{"e.engine_version": f.EngineVersion})
	}
	if f.Owner != "" {
		qb = qb.Where(sq.Eq{"e.owner": f.Owner})
	}
	if !f.Start.IsZero() {
		qb = qb.Where(sq.GtOrEq{"e.collected_at": f.Start})
	}
	if !f.End.IsZero() {
		qb = qb.Where(sq.LtOrEq{"e.collected_at": f.End})
	}
	if f.Limit > 0 {
		qb = qb.Limit(uint64(f.Limit))
	}
	if f.Offset > 0 {
		qb = qb.Offset(uint64(f.Offset))
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query evidence: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	var out []evidence.EvidenceRecord
	for rows.Next() {
		var r evidence.EvidenceRecord
		if err := rows.Scan(
			&r.EvidenceID, &r.PolicyID, &r.TargetID,
			&r.TargetName, &r.TargetType, &r.TargetEnv,
			&r.EngineName, &r.EngineVersion,
			&r.RuleID, &r.RuleName,
			&r.EvalResult, &r.EvalMessage,
			&r.ControlID, &r.ControlCatalogID, &r.ControlCategory,
			&r.RequirementID, &r.PlanID,
			&r.Confidence, &r.ComplianceStatus,
			&r.RiskLevel, &r.Requirements,
			&r.AttestationRef, &r.SourceRegistry, &r.BlobRef,
			&r.CollectedAt,
			&r.LogIndex,
			&r.Classification,
		); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertCertifications batch-inserts certification verdicts.
func (s *Store) InsertCertifications(ctx context.Context, rows []evidence.CertificationRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin certifications tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO certifications (evidence_id, certifier, certifier_version, result, reason, certified_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (evidence_id, certifier)
DO UPDATE SET certifier_version = EXCLUDED.certifier_version,
             result = EXCLUDED.result,
             reason = EXCLUDED.reason,
             certified_at = EXCLUDED.certified_at`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.EvidenceID, r.Certifier, r.CertifierVersion,
			r.Result, r.Reason,
		); err != nil {
			return fmt.Errorf("insert certification: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit certifications: %w", err)
	}
	return nil
}

// QueryCertifications returns certification verdicts for a given evidence row.
func (s *Store) QueryCertifications(
	ctx context.Context, evidenceID string,
) ([]evidence.CertificationRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT evidence_id, certifier, certifier_version, result, reason, certified_at
		 FROM certifications WHERE evidence_id = $1 ORDER BY certified_at DESC`, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("query certifications: %w", err)
	}
	defer rows.Close()

	var out []evidence.CertificationRow
	for rows.Next() {
		var r evidence.CertificationRow
		if err := rows.Scan(
			&r.EvidenceID, &r.Certifier, &r.CertifierVersion,
			&r.Result, &r.Reason, &r.CertifiedAt,
		); err != nil {
			return nil, fmt.Errorf("scan certification: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryRecentEvidence returns lightweight evidence rows for a policy ingested after since.
func (s *Store) QueryRecentEvidence(
	ctx context.Context, policyID string, since time.Time,
) ([]evidence.EvidenceRowLite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT evidence_id, target_id, rule_id, eval_result, compliance_status,
			COALESCE(engine_name, '') AS engine_name,
			COALESCE(source_registry, '') AS source_registry,
			COALESCE(attestation_ref, '') AS attestation_ref,
			collected_at
		 FROM evidence
		 WHERE policy_id = $1 AND ingested_at >= $2
		 ORDER BY ingested_at DESC`, policyID, since)
	if err != nil {
		return nil, fmt.Errorf("query recent evidence: %w", err)
	}
	defer rows.Close()

	var out []evidence.EvidenceRowLite
	for rows.Next() {
		var r evidence.EvidenceRowLite
		if err := rows.Scan(
			&r.EvidenceID, &r.TargetID, &r.RuleID, &r.EvalResult,
			&r.ComplianceStatus, &r.EngineName, &r.SourceRegistry,
			&r.AttestationRef, &r.CollectedAt,
		); err != nil {
			return nil, fmt.Errorf("scan recent evidence: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryEvidenceByLogIndex retrieves publisher data for a given Tessera log index.
// Returns nil if the evidence is not yet in PostgreSQL (async processing delay).
func (s *Store) QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*evidence.WitnessEvidenceRow, error) {
	const q = `SELECT evidence_id, publisher_issuer, submitted_by, publisher_type
	           FROM evidence
	           WHERE log_index = $1
	           LIMIT 1`

	var row evidence.WitnessEvidenceRow
	err := s.pool.QueryRow(ctx, q, logIndex).Scan(&row.EvidenceID, &row.PublisherIssuer, &row.SubmittedBy, &row.PublisherType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query evidence by log_index: %w", err)
	}

	return &row, nil
}

// IsIndexWitnessed checks if a Tessera log index has been verified and countersigned by the witness.
func (s *Store) IsIndexWitnessed(ctx context.Context, index uint64) bool {
	const q = `SELECT EXISTS(SELECT 1 FROM witnessed_indices WHERE log_index = $1)`

	var exists bool
	err := s.pool.QueryRow(ctx, q, index).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// MarkIndexWitnessed records that a Tessera log index has been verified and countersigned.
func (s *Store) MarkIndexWitnessed(ctx context.Context, index uint64, witnessName, checkpointHash string) error {
	const q = `INSERT INTO witnessed_indices (log_index, witness_name, checkpoint_hash)
	           VALUES ($1, $2, $3)
	           ON CONFLICT (log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q, index, witnessName, checkpointHash)
	if err != nil {
		return fmt.Errorf("mark index witnessed: %w", err)
	}
	return nil
}
