// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Policy represents a stored policy artifact.
type Policy struct {
	PolicyID     string    `json:"policy_id"`
	Title        string    `json:"title"`
	Version      string    `json:"version,omitempty"`
	OCIReference string    `json:"oci_reference"`
	Content      string    `json:"content"`
	ImportedAt   time.Time `json:"imported_at"`
	ImportedBy   string    `json:"imported_by,omitempty"`

	// Dimensional metadata for policy enrollment
	Technologies            []string   `json:"technologies,omitempty"`
	Geopolitical            []string   `json:"geopolitical,omitempty"`
	Sensitivity             []string   `json:"sensitivity,omitempty"`
	Users                   []string   `json:"users,omitempty"`
	Groups                  []string   `json:"groups,omitempty"`
	EvaluationTimelineStart *time.Time `json:"evaluation_timeline_start,omitempty"`
	EvaluationTimelineEnd   *time.Time `json:"evaluation_timeline_end,omitempty"`
	BundleID                string     `json:"bundle_id,omitempty"`
	TesseraLogIndex         *uint64    `json:"tessera_log_index,omitempty"`
}

// InsertPolicy stores a policy artifact (upsert on policy_id).
func (s *Store) InsertPolicy(ctx context.Context, p Policy) error {
	if p.PolicyID == "" {
		p.PolicyID = uuid.New().String()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO policies (policy_id, title, version, oci_reference, content, imported_by,
		   technologies, geopolitical, sensitivity, users, groups,
		   evaluation_timeline_start, evaluation_timeline_end,
		   bundle_id, tessera_log_index)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (policy_id) DO UPDATE SET
		   title         = EXCLUDED.title,
		   version       = EXCLUDED.version,
		   oci_reference = EXCLUDED.oci_reference,
		   content       = EXCLUDED.content,
		   imported_by   = EXCLUDED.imported_by,
		   technologies  = EXCLUDED.technologies,
		   geopolitical  = EXCLUDED.geopolitical,
		   sensitivity   = EXCLUDED.sensitivity,
		   users         = EXCLUDED.users,
		   groups        = EXCLUDED.groups,
		   evaluation_timeline_start = EXCLUDED.evaluation_timeline_start,
		   evaluation_timeline_end   = EXCLUDED.evaluation_timeline_end,
		   bundle_id     = EXCLUDED.bundle_id,
		   tessera_log_index = EXCLUDED.tessera_log_index,
		   imported_at   = now()`,
		p.PolicyID, p.Title, p.Version, p.OCIReference, p.Content, p.ImportedBy,
		p.Technologies, p.Geopolitical, p.Sensitivity, p.Users, p.Groups,
		p.EvaluationTimelineStart, p.EvaluationTimelineEnd,
		nullStr(p.BundleID), p.TesseraLogIndex,
	)
	return err
}

// ListPolicies returns all stored policies ordered by import date.
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT policy_id, title, version, oci_reference, imported_at, COALESCE(imported_by, '') FROM policies ORDER BY imported_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.PolicyID, &p.Title, &p.Version, &p.OCIReference, &p.ImportedAt, &p.ImportedBy); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicy returns a single policy with full content.
func (s *Store) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT policy_id, title, version, oci_reference, content, imported_at, COALESCE(imported_by, '') FROM policies WHERE policy_id = $1`, policyID)
	var p Policy
	if err := row.Scan(&p.PolicyID, &p.Title, &p.Version, &p.OCIReference, &p.Content, &p.ImportedAt, &p.ImportedBy); err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	return &p, nil
}

// PolicyExistsByID checks if a policy with the given ID exists in the database.
func (s *Store) PolicyExistsByID(ctx context.Context, policyID string) bool {
	const q = `SELECT EXISTS(SELECT 1 FROM policies WHERE policy_id = $1)`

	var exists bool
	err := s.pool.QueryRow(ctx, q, policyID).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (s *Store) QueryPoliciesByDimensions(ctx context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error) {
	const q = `SELECT policy_id, title, version, tessera_log_index,
		technologies, geopolitical, sensitivity,
		evaluation_timeline_start, evaluation_timeline_end
	FROM policies
	WHERE (
		technologies && $1
		OR geopolitical && $2
		OR sensitivity && $3
		OR users && $4
		OR groups && $5
	)
	AND (evaluation_timeline_start IS NULL OR evaluation_timeline_start <= $6)
	AND (evaluation_timeline_end IS NULL OR evaluation_timeline_end >= $6)
	ORDER BY tessera_log_index ASC`

	rows, err := s.pool.Query(ctx, q,
		dims.Technologies, dims.Geopolitical, dims.Sensitivity,
		dims.Users, dims.Groups, dims.Timestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("query policies by dimensions: %w", err)
	}
	defer rows.Close()

	var out []PolicyWithDimensions
	for rows.Next() {
		var p PolicyWithDimensions
		var logIndex *int64
		if err := rows.Scan(
			&p.PolicyID, &p.Title, &p.Version, &logIndex,
			&p.Technologies, &p.Geopolitical, &p.Sensitivity,
			&p.EvaluationStart, &p.EvaluationEnd,
		); err != nil {
			return nil, fmt.Errorf("scan policy dimension row: %w", err)
		}
		if logIndex != nil {
			p.LogIndex = uint64(*logIndex) //nolint:gosec // G115: DB value
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
