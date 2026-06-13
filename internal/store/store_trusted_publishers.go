// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func (s *Store) InsertTrustedPublishers(ctx context.Context, rows []requirements.TrustedPublisherRow) error {
	if len(rows) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin trusted publishers tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO target_trusted_publishers
		(target_id, issuer, sub_pattern, environment, added_at, added_by, tessera_log_index)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (target_id, issuer, sub_pattern)
		DO UPDATE SET environment = EXCLUDED.environment,
		              added_at = EXCLUDED.added_at,
		              added_by = EXCLUDED.added_by,
		              tessera_log_index = EXCLUDED.tessera_log_index`

	for _, r := range rows {
		addedAt := r.AddedAt
		if addedAt.IsZero() {
			addedAt = time.Now()
		}
		if _, err := tx.Exec(ctx, q,
			r.TargetID, r.Issuer, r.SubPattern, r.Environment,
			addedAt, r.AddedBy, r.TesseraLogIndex,
		); err != nil {
			return classifyErr(fmt.Errorf("insert trusted publisher: %w", err))
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return classifyErr(fmt.Errorf("commit trusted publishers: %w", err))
	}
	return nil
}

func (s *Store) GetTrustedPublishers(ctx context.Context, targetID string) ([]requirements.TrustedPublisherRow, error) {
	const q = `SELECT target_id, issuer, sub_pattern, environment,
		added_at, added_by, tessera_log_index
		FROM target_trusted_publishers
		WHERE target_id = $1
		ORDER BY added_at`

	rows, err := s.pool.Query(ctx, q, targetID)
	if err != nil {
		return nil, fmt.Errorf("get trusted publishers: %w", err)
	}
	defer rows.Close()

	out := make([]requirements.TrustedPublisherRow, 0)
	for rows.Next() {
		var r requirements.TrustedPublisherRow
		if err := rows.Scan(
			&r.TargetID, &r.Issuer, &r.SubPattern, &r.Environment,
			&r.AddedAt, &r.AddedBy, &r.TesseraLogIndex,
		); err != nil {
			return nil, fmt.Errorf("scan trusted publisher: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTrustedPublishers(ctx context.Context, targetID string) error {
	const q = `DELETE FROM target_trusted_publishers WHERE target_id = $1`
	if _, err := s.pool.Exec(ctx, q, targetID); err != nil {
		return classifyErr(fmt.Errorf("delete trusted publishers: %w", err))
	}
	return nil
}
