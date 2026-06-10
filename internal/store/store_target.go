// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// IsTargetRegistered checks if a target has any registration in the targets table.
func (s *Store) IsTargetRegistered(ctx context.Context, targetID string) bool {
	const q = `SELECT EXISTS(SELECT 1 FROM targets WHERE target_id = $1)`
	var exists bool
	err := s.pool.QueryRow(ctx, q, targetID).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// InsertBundleArtifact stores a bundle artifact row.
func (s *Store) InsertBundleArtifact(ctx context.Context, b requirements.BundleArtifactRow) error {
	const q = `INSERT INTO bundle_artifacts (bundle_id, tessera_log_index, artifact_type, artifact_id, oci_reference)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (bundle_id, tessera_log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q, b.BundleID, b.TesseraLogIndex, b.ArtifactType, b.ArtifactID, nullStr(b.OCIReference))
	if err != nil {
		return fmt.Errorf("insert bundle artifact: %w", err)
	}
	return nil
}

func (s *Store) InsertTarget(ctx context.Context, t requirements.TargetRow) error {
	const q = `INSERT INTO targets (
		target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	ON CONFLICT (target_id, tessera_log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q,
		t.TargetID, t.TesseraLogIndex, t.TargetName, t.TargetType,
		t.Technologies, t.Geopolitical, t.Sensitivity, t.Users, t.Groups,
		t.RegisteredAt, t.RegisteredBy,
	)
	if err != nil {
		return fmt.Errorf("insert target: %w", err)
	}
	return nil
}

func (s *Store) GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*requirements.TargetRow, error) {
	const q = `SELECT target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	FROM targets
	WHERE target_id = $1 AND registered_at <= $2
	ORDER BY registered_at DESC
	LIMIT 1`

	var t requirements.TargetRow
	err := s.pool.QueryRow(ctx, q, targetID, asOf).Scan(
		&t.TargetID, &t.TesseraLogIndex, &t.TargetName, &t.TargetType,
		&t.Technologies, &t.Geopolitical, &t.Sensitivity, &t.Users, &t.Groups,
		&t.RegisteredAt, &t.RegisteredBy,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest target: %w", err)
	}
	return &t, nil
}

func (s *Store) ListTargets(ctx context.Context) ([]requirements.TargetRow, error) {
	const q = `SELECT DISTINCT ON (target_id)
		target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	FROM targets
	ORDER BY target_id, registered_at DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()

	var out []requirements.TargetRow
	for rows.Next() {
		var t requirements.TargetRow
		if err := rows.Scan(
			&t.TargetID, &t.TesseraLogIndex, &t.TargetName, &t.TargetType,
			&t.Technologies, &t.Geopolitical, &t.Sensitivity, &t.Users, &t.Groups,
			&t.RegisteredAt, &t.RegisteredBy,
		); err != nil {
			return nil, fmt.Errorf("scan target row: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
