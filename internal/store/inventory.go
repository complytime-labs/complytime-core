// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"strings"
)

// ListInventory returns per-target aggregates using the latest evidence row
// per (target_id, policy_id), ordered by target_id.
func (s *Store) ListInventory(ctx context.Context, f InventoryFilter) ([]InventoryItem, error) {
	var where []string
	args := []any{}
	n := 1

	where = append(where, `e.target_id <> ''`)
	if f.PolicyID != "" {
		where = append(where, fmt.Sprintf(`e.policy_id = $%d`, n))
		args = append(args, f.PolicyID)
		n++
	}
	if f.ProgramID != "" {
		where = append(where, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM workbench.programs pr
			WHERE pr.id = $%d::uuid AND pr.deleted_at IS NULL
				AND e.policy_id = ANY(pr.policy_ids)
		)`, n))
		args = append(args, f.ProgramID)
		n++
	}
	if f.TargetType != "" {
		where = append(where, fmt.Sprintf(`COALESCE(e.target_type, '') = $%d`, n))
		args = append(args, f.TargetType)
		n++
	}
	if f.Environment != "" {
		where = append(where, fmt.Sprintf(`COALESCE(e.target_env, '') = $%d`, n))
		args = append(args, f.Environment)
	}

	q := fmt.Sprintf(`
		WITH ranked AS (
			SELECT DISTINCT ON (e.target_id, e.policy_id)
				e.target_id,
				COALESCE(e.target_type, '') AS target_type,
				COALESCE(e.target_env, '') AS target_env,
				e.policy_id,
				e.eval_result,
				e.collected_at
			FROM evidence e
			WHERE %s
			ORDER BY e.target_id, e.policy_id, e.collected_at DESC
		)
		SELECT
			target_id,
			(array_agg(target_type ORDER BY collected_at DESC))[1] AS target_type,
			(array_agg(target_env ORDER BY collected_at DESC))[1] AS target_env,
			COUNT(*)::int AS policy_count,
			COUNT(*) FILTER (WHERE eval_result = 'Passed')::int AS pass_count,
			COUNT(*) FILTER (WHERE eval_result = 'Failed')::int AS fail_count,
			MAX(collected_at) AS latest_evidence
		FROM ranked
		GROUP BY target_id
		ORDER BY target_id`,
		strings.Join(where, " AND "))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list inventory: %w", err)
	}
	defer rows.Close()

	var out []InventoryItem
	for rows.Next() {
		var it InventoryItem
		if err := rows.Scan(
			&it.TargetID, &it.TargetType, &it.Environment,
			&it.PolicyCount, &it.PassCount, &it.FailCount,
			&it.LatestEvidence,
		); err != nil {
			return nil, fmt.Errorf("scan inventory: %w", err)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inventory: %w", err)
	}
	if out == nil {
		out = []InventoryItem{}
	}
	return out, nil
}
