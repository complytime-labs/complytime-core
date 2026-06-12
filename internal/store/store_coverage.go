// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/complytime-labs/complytime-core/internal/posture"
)

// QueryCoverage returns requirement-level gap analysis for a policy:
// which requirements have evidence, which don't, which have stale
// evidence (per adherence frequency), and which evidence is unaligned
// to any specific requirement.
func (s *Store) QueryCoverage(ctx context.Context, f posture.CoverageFilter) (*posture.CoverageResult, error) {
	allReqs, err := s.policyRequirementIDs(ctx, f.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("query requirements: %w", err)
	}
	if len(allReqs) == 0 {
		return nil, classifyErr(fmt.Errorf("no requirements found for policy %s: %w", f.PolicyID, ErrNotFound))
	}

	coveredSet, latestByReq, err := s.coveredRequirementIDs(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("query covered requirements: %w", err)
	}

	unaligned, err := s.unalignedControlIDs(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("query unaligned evidence: %w", err)
	}

	var covered, gaps, stale []string
	for _, rid := range allReqs {
		if coveredSet[rid] {
			covered = append(covered, rid)
			if latest, ok := latestByReq[rid]; ok {
				maxAge := s.reqMaxAge(rid, f)
				if maxAge > 0 && time.Since(latest) > maxAge {
					stale = append(stale, rid)
				}
			}
		} else {
			gaps = append(gaps, rid)
		}
	}

	total := len(allReqs)
	coveredCount := len(covered)
	pct := 0.0
	if total > 0 {
		pct = math.Round(float64(coveredCount)/float64(total)*1000) / 10
	}

	return &posture.CoverageResult{
		PolicyID:            f.PolicyID,
		TotalRequirements:   total,
		CoveredRequirements: coveredCount,
		CoveragePct:         pct,
		Covered:             covered,
		Gaps:                gaps,
		Stale:               stale,
		Unaligned:           unaligned,
	}, nil
}

// reqMaxAge returns the staleness threshold for a requirement, preferring
// the per-requirement adherence frequency over the fallback MaxAge.
func (s *Store) reqMaxAge(reqID string, f posture.CoverageFilter) time.Duration {
	if f.Freshness != nil {
		if d, ok := f.Freshness[reqID]; ok {
			return d
		}
	}
	return f.MaxAge
}

func (s *Store) policyRequirementIDs(ctx context.Context, policyID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ar.requirement_id
		FROM assessment_requirements ar
		INNER JOIN controls c
			ON c.catalog_id = ar.catalog_id AND c.control_id = ar.control_id
		WHERE c.policy_id = $1
		ORDER BY ar.requirement_id`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}

func (s *Store) coveredRequirementIDs(ctx context.Context, f posture.CoverageFilter) (map[string]bool, map[string]time.Time, error) {
	q := `SELECT requirement_id, MAX(collected_at) as latest
		FROM evidence
		WHERE policy_id = $1 AND requirement_id != ''`
	args := []any{f.PolicyID}
	argIdx := 2

	if f.TargetID != "" {
		q += fmt.Sprintf(` AND target_id = $%d`, argIdx)
		args = append(args, f.TargetID)
		argIdx++
	}
	if !f.Since.IsZero() {
		q += fmt.Sprintf(` AND collected_at >= $%d`, argIdx)
		args = append(args, f.Since)
	}
	q += ` GROUP BY requirement_id`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	covered := make(map[string]bool)
	latest := make(map[string]time.Time)
	for rows.Next() {
		var rid string
		var t time.Time
		if err := rows.Scan(&rid, &t); err != nil {
			return nil, nil, err
		}
		covered[rid] = true
		latest[rid] = t
	}

	return covered, latest, rows.Err()
}

func (s *Store) unalignedControlIDs(ctx context.Context, f posture.CoverageFilter) ([]string, error) {
	q := `SELECT DISTINCT control_id
		FROM evidence
		WHERE policy_id = $1 AND (requirement_id = '' OR requirement_id IS NULL)`
	args := []any{f.PolicyID}
	argIdx := 2

	if f.TargetID != "" {
		q += fmt.Sprintf(` AND target_id = $%d`, argIdx)
		args = append(args, f.TargetID)
		argIdx++
	}
	if !f.Since.IsZero() {
		q += fmt.Sprintf(` AND collected_at >= $%d`, argIdx)
		args = append(args, f.Since)
	}
	q += ` ORDER BY control_id`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		out = append(out, cid)
	}
	return out, rows.Err()
}

// Compile-time interface check.
var _ posture.CoverageStore = (*Store)(nil)
