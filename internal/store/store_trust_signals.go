// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/complytime-labs/complytime-core/internal/certifier"
)

// TrustSignalRow represents a single trust signal record in the database.
type TrustSignalRow struct {
	EvidenceID string           `json:"evidence_id"`
	Layer      string           `json:"layer"`
	CheckName  string           `json:"check_name"`
	Result     certifier.Result `json:"result"`
	Reason     string           `json:"reason"`
	CheckedAt  time.Time        `json:"checked_at"`
}

// TrustSignalFilter holds query parameters for trust signal queries.
type TrustSignalFilter struct {
	EvidenceID string
	Layer      string
	CheckName  string
	Result     certifier.Result
	Limit      int
	Offset     int
}

// InsertTrustSignals batch-inserts trust signal records.
// Uses upsert semantics: if a signal (evidence_id, layer, check_name) already exists,
// it updates result/reason/checked_at to reflect the latest check run.
func (s *Store) InsertTrustSignals(ctx context.Context, signals []TrustSignalRow) error {
	if len(signals) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin trust signals tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason, checked_at)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (evidence_id, layer, check_name)
	DO UPDATE SET result = EXCLUDED.result,
	              reason = EXCLUDED.reason,
	              checked_at = EXCLUDED.checked_at`

	for _, sig := range signals {
		checkedAt := sig.CheckedAt
		if checkedAt.IsZero() {
			checkedAt = time.Now()
		}
		if _, err := tx.Exec(ctx, q,
			sig.EvidenceID, sig.Layer, sig.CheckName, sig.Result, sig.Reason, checkedAt,
		); err != nil {
			return fmt.Errorf("insert trust signal: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit trust signals: %w", err)
	}
	return nil
}

// QueryTrustSignals retrieves all trust signals for a given evidence ID.
func (s *Store) QueryTrustSignals(ctx context.Context, evidenceID string) ([]TrustSignalRow, error) {
	query := `SELECT evidence_id, layer, check_name, result, reason, checked_at
	          FROM trust_signals
	          WHERE evidence_id = $1
	          ORDER BY checked_at DESC`

	rows, err := s.pool.Query(ctx, query, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("query trust signals: %w", err)
	}
	defer rows.Close()

	var out []TrustSignalRow
	for rows.Next() {
		var r TrustSignalRow
		if err := rows.Scan(
			&r.EvidenceID, &r.Layer, &r.CheckName, &r.Result, &r.Reason, &r.CheckedAt,
		); err != nil {
			return nil, fmt.Errorf("scan trust signal: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HasFailedTrustSignals returns true if any trust signal for this evidence has result='fail' or 'error'.
// Used by witness to determine if evidence passed certification.
func (s *Store) HasFailedTrustSignals(ctx context.Context, evidenceID string) (bool, error) {
	var hasFailed bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM trust_signals
			WHERE evidence_id = $1
			AND result IN ('fail', 'error')
		)
	`, evidenceID).Scan(&hasFailed)
	return hasFailed, err
}
