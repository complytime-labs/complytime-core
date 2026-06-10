// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"strconv"
)

// ListRequirementMatrix returns requirement rows with evidence aggregates.
// Uses evidence as the base table so rows appear even when
// assessment_requirements has not been populated (no catalog import).
// When assessment_requirements IS populated, requirement text and IDs
// are joined in; otherwise those columns are empty and the view is
// control-level.
func (s *Store) ListRequirementMatrix(ctx context.Context, f RequirementFilter) ([]RequirementRow, error) {
	query := `
		SELECT
			COALESCE(ar.catalog_id, '') AS catalog_id,
			e.control_id,
			COALESCE(c.title, '') AS control_title,
			COALESCE(ar.requirement_id, e.control_id) AS requirement_id,
			COALESCE(ar.text, c.objective) AS requirement_text,
			COUNT(DISTINCT e.evidence_id) AS evidence_count,
			CASE WHEN COUNT(e.evidence_id) > 0 THEN MAX(e.collected_at)::TEXT ELSE '' END AS latest_evidence,
			CASE
				WHEN COUNT(e.evidence_id) = 0 THEN 'No Evidence'
				WHEN COUNT(DISTINCT e.evidence_id) FILTER (WHERE e.eval_result = 'Failed') > 0
					AND COUNT(DISTINCT e.evidence_id) FILTER (WHERE e.eval_result = 'Passed') > 0 THEN 'Mixed'
				WHEN COUNT(DISTINCT e.evidence_id) FILTER (WHERE e.eval_result = 'Passed') = COUNT(DISTINCT e.evidence_id) THEN 'Passing'
				WHEN COUNT(DISTINCT e.evidence_id) FILTER (WHERE e.eval_result = 'Failed') = COUNT(DISTINCT e.evidence_id) THEN 'Failing'
				ELSE 'Inconclusive'
			END AS classification
		FROM evidence e
		LEFT JOIN controls c
			ON c.control_id = e.control_id AND c.policy_id = e.policy_id
		LEFT JOIN assessment_requirements ar
			ON ar.control_id = e.control_id AND ar.catalog_id = c.catalog_id
		WHERE e.policy_id = $1`

	args := []any{f.PolicyID}
	argN := 2
	if !f.Start.IsZero() {
		query += ` AND e.collected_at >= $` + strconv.Itoa(argN)
		args = append(args, f.Start)
		argN++
	}
	if !f.End.IsZero() {
		query += ` AND e.collected_at <= $` + strconv.Itoa(argN)
		args = append(args, f.End)
		argN++
	}
	if f.ControlFamily != "" {
		query += ` AND e.control_id LIKE $` + strconv.Itoa(argN) + ` || '%'`
		args = append(args, f.ControlFamily)
	}

	query += ` GROUP BY COALESCE(ar.catalog_id, ''), e.control_id, COALESCE(c.title, ''),
			COALESCE(ar.requirement_id, e.control_id), COALESCE(ar.text, c.objective)
		ORDER BY e.control_id, requirement_id`

	if f.Limit <= 0 {
		f.Limit = 100
	}
	query += fmt.Sprintf(` LIMIT %d`, f.Limit)
	if f.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, f.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list requirement matrix: %w", err)
	}
	defer rows.Close()

	var out []RequirementRow
	for rows.Next() {
		var r RequirementRow
		if err := rows.Scan(
			&r.CatalogID, &r.ControlID, &r.ControlTitle,
			&r.RequirementID, &r.RequirementText,
			&r.EvidenceCount, &r.LatestEvidence,
			&r.Classification,
		); err != nil {
			return nil, fmt.Errorf("scan requirement matrix row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// requirementKnownForPolicy reports whether requirementID refers to at least
// one assessment requirement for the policy's controls or to evidence rows for
// that policy (control_id or requirement_id match).
func (s *Store) requirementKnownForPolicy(ctx context.Context, policyID, requirementID string) (bool, error) {
	var evCount int64
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM evidence WHERE policy_id = $1 AND (control_id = $2 OR requirement_id = $3)`,
		policyID, requirementID, requirementID,
	).Scan(&evCount); err != nil {
		return false, fmt.Errorf("count evidence for requirement: %w", err)
	}
	if evCount > 0 {
		return true, nil
	}

	var arCount int64
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM assessment_requirements ar
		 INNER JOIN controls c
		   ON c.catalog_id = ar.catalog_id AND c.control_id = ar.control_id
		 WHERE ar.requirement_id = $1 AND c.policy_id = $2`,
		requirementID, policyID,
	).Scan(&arCount); err != nil {
		return false, fmt.Errorf("count assessment requirements for requirement: %w", err)
	}
	return arCount > 0, nil
}

// ListRequirementEvidence returns evidence rows for a specific requirement.
func (s *Store) ListRequirementEvidence(ctx context.Context, requirementID string, f RequirementFilter) ([]RequirementEvidenceRow, error) {
	known, err := s.requirementKnownForPolicy(ctx, f.PolicyID, requirementID)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, ErrRequirementNotFound
	}

	query := `
		SELECT
			e.evidence_id,
			e.target_id,
			COALESCE(e.target_name, '') AS target_name,
			e.rule_id,
			e.eval_result,
			COALESCE(ea_latest.classification, '') AS classification,
			COALESCE(ea_latest.last_assessed::TEXT, '') AS assessed_at,
			e.collected_at::TEXT AS collected_at,
			COALESCE(e.source_registry, '') AS source_registry
		FROM evidence e
		LEFT JOIN LATERAL (
			SELECT ea2.classification, ea2.assessed_at AS last_assessed
			FROM evidence_assessments ea2
			WHERE ea2.evidence_id = e.evidence_id
			ORDER BY ea2.assessed_at DESC
			LIMIT 1
		) AS ea_latest ON TRUE
		WHERE (e.control_id = $1 OR e.control_id IN (
			SELECT control_id FROM assessment_requirements
			WHERE requirement_id = $2
		)) AND e.policy_id = $3`

	args := []any{requirementID, requirementID, f.PolicyID}
	argN := 4
	if !f.Start.IsZero() {
		query += ` AND e.collected_at >= $` + strconv.Itoa(argN)
		args = append(args, f.Start)
		argN++
	}
	if !f.End.IsZero() {
		query += ` AND e.collected_at <= $` + strconv.Itoa(argN)
		args = append(args, f.End)
	}

	query += ` ORDER BY e.collected_at DESC`

	if f.Limit <= 0 {
		f.Limit = 100
	}
	query += fmt.Sprintf(` LIMIT %d`, f.Limit)
	if f.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, f.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list requirement evidence: %w", err)
	}
	defer rows.Close()

	var out []RequirementEvidenceRow
	for rows.Next() {
		var r RequirementEvidenceRow
		if err := rows.Scan(
			&r.EvidenceID, &r.TargetID, &r.TargetName,
			&r.RuleID, &r.EvalResult,
			&r.Classification, &r.AssessedAt,
			&r.CollectedAt, &r.SourceRegistry,
		); err != nil {
			return nil, fmt.Errorf("scan requirement evidence row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
