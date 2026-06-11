// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/complytime-labs/complytime-core/internal/posture"
)

// QueryCoverage returns gap analysis for a policy: which controls have
// evidence, which don't, and which have stale evidence.
func (s *Store) QueryCoverage(ctx context.Context, f posture.CoverageFilter) (*posture.CoverageResult, error) {
	allControls, err := s.policyControlIDs(ctx, f.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("query controls: %w", err)
	}
	if len(allControls) == 0 {
		return nil, classifyErr(fmt.Errorf("no controls found for policy %s: %w", f.PolicyID, ErrNotFound))
	}

	coveredSet, latestByControl, err := s.coveredControlIDs(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("query covered controls: %w", err)
	}

	var covered, gaps, stale []string
	for _, cid := range allControls {
		if coveredSet[cid] {
			covered = append(covered, cid)
			if f.MaxAge > 0 {
				if latest, ok := latestByControl[cid]; ok {
					if time.Since(latest) > f.MaxAge {
						stale = append(stale, cid)
					}
				}
			}
		} else {
			gaps = append(gaps, cid)
		}
	}

	total := len(allControls)
	coveredCount := len(covered)
	pct := 0.0
	if total > 0 {
		pct = math.Round(float64(coveredCount)/float64(total)*1000) / 10
	}

	return &posture.CoverageResult{
		PolicyID:        f.PolicyID,
		TotalControls:   total,
		CoveredControls: coveredCount,
		CoveragePct:     pct,
		Covered:         covered,
		Gaps:            gaps,
		Stale:           stale,
	}, nil
}

func (s *Store) policyControlIDs(ctx context.Context, policyID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT control_id FROM controls WHERE policy_id = $1 ORDER BY control_id`, policyID)
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

func (s *Store) coveredControlIDs(ctx context.Context, f posture.CoverageFilter) (map[string]bool, map[string]time.Time, error) {
	q := `SELECT control_id, MAX(collected_at) as latest
		FROM evidence
		WHERE policy_id = $1`
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
	q += ` GROUP BY control_id`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	covered := make(map[string]bool)
	latest := make(map[string]time.Time)
	for rows.Next() {
		var cid string
		var t time.Time
		if err := rows.Scan(&cid, &t); err != nil {
			return nil, nil, err
		}
		covered[cid] = true
		latest[cid] = t
	}

	return covered, latest, rows.Err()
}

// Compile-time interface check.
var _ posture.CoverageStore = (*Store)(nil)
