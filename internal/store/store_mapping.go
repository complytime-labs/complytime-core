// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/google/uuid"
)

// InsertMapping stores a mapping document.
func (s *Store) InsertMapping(ctx context.Context, m MappingDocument) error {
	if m.MappingID == "" {
		m.MappingID = uuid.New().String()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO mapping_documents (mapping_id, source_catalog_id, target_catalog_id, framework, content)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (mapping_id) DO UPDATE SET
		   source_catalog_id = EXCLUDED.source_catalog_id,
		   target_catalog_id = EXCLUDED.target_catalog_id,
		   framework = EXCLUDED.framework,
		   content = EXCLUDED.content,
		   imported_at = now()`,
		m.MappingID, m.SourceCatalogID, m.TargetCatalogID, m.Framework, m.Content,
	)
	return err
}

// ListMappings returns mapping documents for a given source catalog (backward-compat shim).
func (s *Store) ListMappings(ctx context.Context, policyID string) ([]MappingDocument, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT mapping_id, source_catalog_id, target_catalog_id, framework, content, imported_at
		 FROM mapping_documents WHERE source_catalog_id = $1 OR target_catalog_id = $1
		 ORDER BY imported_at DESC`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer rows.Close()

	var out []MappingDocument
	for rows.Next() {
		var m MappingDocument
		if err := rows.Scan(&m.MappingID, &m.SourceCatalogID, &m.TargetCatalogID, &m.Framework, &m.Content, &m.ImportedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListAllMappings returns all mapping documents.
func (s *Store) ListAllMappings(ctx context.Context) ([]MappingDocument, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT mapping_id, source_catalog_id, target_catalog_id, framework, content, imported_at
		 FROM mapping_documents ORDER BY imported_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all mappings: %w", err)
	}
	defer rows.Close()

	var out []MappingDocument
	for rows.Next() {
		var m MappingDocument
		if err := rows.Scan(&m.MappingID, &m.SourceCatalogID, &m.TargetCatalogID, &m.Framework, &m.Content, &m.ImportedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// QueryMappings returns mapping entries for a given source/target catalog pair.
func (s *Store) QueryMappings(ctx context.Context, sourceCatalogID, targetCatalogID string, limit int) ([]gemara.MappingEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	qb := psql.Select("mapping_id", "source_catalog_id", "target_catalog_id", "guideline_id",
		"control_id", "requirement_id", "framework", "reference", "strength", "confidence").
		From("mapping_entries").
		OrderBy("guideline_id", "control_id").
		Limit(uint64(limit))
	if sourceCatalogID != "" {
		qb = qb.Where(sq.Eq{"source_catalog_id": sourceCatalogID})
	}
	if targetCatalogID != "" {
		qb = qb.Where(sq.Eq{"target_catalog_id": targetCatalogID})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query mappings: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query mappings: %w", err)
	}
	defer rows.Close()

	var out []gemara.MappingEntry
	for rows.Next() {
		var e gemara.MappingEntry
		if err := rows.Scan(
			&e.MappingID, &e.SourceCatalogID, &e.TargetCatalogID, &e.GuidelineID,
			&e.ControlID, &e.RequirementID, &e.Framework, &e.Reference,
			&e.Strength, &e.Confidence,
		); err != nil {
			return nil, fmt.Errorf("scan mapping entry: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mapping entries: %w", err)
	}
	if out == nil {
		out = []gemara.MappingEntry{}
	}
	return out, nil
}

// InsertMappingEntries batch-inserts structured mapping entries within a transaction.
func (s *Store) InsertMappingEntries(ctx context.Context, entries []gemara.MappingEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin mapping entries tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO mapping_entries
		(mapping_id, source_catalog_id, target_catalog_id, guideline_id, control_id, requirement_id, framework, reference, strength, confidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (mapping_id, source_catalog_id, guideline_id, target_catalog_id, control_id)
		DO UPDATE SET strength = EXCLUDED.strength, confidence = EXCLUDED.confidence`
	for _, e := range entries {
		if _, err := tx.Exec(ctx, q,
			e.MappingID, e.SourceCatalogID, e.TargetCatalogID, e.GuidelineID,
			e.ControlID, e.RequirementID, e.Framework, e.Reference,
			e.Strength, e.Confidence,
		); err != nil {
			return fmt.Errorf("insert mapping entry: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit mapping entries: %w", err)
	}
	return nil
}

// DeleteMappingEntries removes all entries for a given source/target catalog pair.
func (s *Store) DeleteMappingEntries(ctx context.Context, sourceCatalogID, targetCatalogID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM mapping_entries WHERE source_catalog_id = $1 AND target_catalog_id = $2`,
		sourceCatalogID, targetCatalogID)
	return err
}

// CountMappingEntries returns the number of structured entries for a given mapping document.
func (s *Store) CountMappingEntries(ctx context.Context, mappingID string) (int, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mapping_entries WHERE mapping_id = $1`, mappingID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count mapping entries: %w", err)
	}
	return int(count), nil
}
