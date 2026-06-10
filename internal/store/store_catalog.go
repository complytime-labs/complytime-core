// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/gemara"
)

// InsertCatalog stores a raw catalog artifact, replacing on conflict.
func (s *Store) InsertCatalog(ctx context.Context, c Catalog) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO catalogs (catalog_id, catalog_type, title, content, policy_id) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (catalog_id) DO UPDATE SET
		   catalog_type = EXCLUDED.catalog_type,
		   title = EXCLUDED.title,
		   content = EXCLUDED.content,
		   policy_id = EXCLUDED.policy_id,
		   imported_at = now()`,
		c.CatalogID, c.CatalogType, c.Title, c.Content, c.PolicyID,
	)
	return err
}

// ListCatalogs returns all stored catalogs (without content for efficiency).
func (s *Store) ListCatalogs(ctx context.Context) ([]Catalog, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT catalog_id, catalog_type, title, policy_id, imported_at FROM catalogs ORDER BY imported_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list catalogs: %w", err)
	}
	defer rows.Close()

	var out []Catalog
	for rows.Next() {
		var c Catalog
		if err := rows.Scan(&c.CatalogID, &c.CatalogType, &c.Title, &c.PolicyID, &c.ImportedAt); err != nil {
			return nil, fmt.Errorf("scan catalog: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCatalog returns a single catalog with full content.
func (s *Store) GetCatalog(ctx context.Context, catalogID string) (*Catalog, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT catalog_id, catalog_type, title, content, policy_id, imported_at FROM catalogs WHERE catalog_id = $1`, catalogID)
	var c Catalog
	if err := row.Scan(&c.CatalogID, &c.CatalogType, &c.Title, &c.Content, &c.PolicyID, &c.ImportedAt); err != nil {
		return nil, fmt.Errorf("get catalog: %w", err)
	}
	return &c, nil
}

func (s *Store) InsertControls(ctx context.Context, rows []gemara.ControlRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin controls tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO controls (catalog_id, control_id, title, objective, group_id, state, policy_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (catalog_id, control_id) DO UPDATE SET
		  title = EXCLUDED.title,
		  objective = EXCLUDED.objective,
		  group_id = EXCLUDED.group_id,
		  state = EXCLUDED.state,
		  policy_id = EXCLUDED.policy_id`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.ControlID, r.Title, r.Objective, r.GroupID, r.State, r.PolicyID,
		); err != nil {
			return fmt.Errorf("insert control: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit controls: %w", err)
	}
	return nil
}

func (s *Store) InsertAssessmentRequirements(ctx context.Context, rows []gemara.AssessmentRequirementRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin assessment requirements tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO assessment_requirements (catalog_id, control_id, requirement_id, text, applicability, recommendation, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (catalog_id, control_id, requirement_id) DO UPDATE SET
		  text = EXCLUDED.text,
		  applicability = EXCLUDED.applicability,
		  recommendation = EXCLUDED.recommendation,
		  state = EXCLUDED.state`
	for _, r := range rows {
		app := r.Applicability
		if app == nil {
			app = []string{}
		}
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.ControlID, r.RequirementID, r.Text, app, r.Recommendation, r.State,
		); err != nil {
			return fmt.Errorf("insert assessment requirement: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit assessment requirements: %w", err)
	}
	return nil
}

func (s *Store) InsertControlThreats(ctx context.Context, rows []gemara.ControlThreatRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin control threats tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO control_threats (catalog_id, control_id, threat_reference_id, threat_entry_id) VALUES ($1, $2, $3, $4)`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.ControlID, r.ThreatReferenceID, r.ThreatEntryID,
		); err != nil {
			return fmt.Errorf("insert control threat: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit control threats: %w", err)
	}
	return nil
}

func (s *Store) InsertGuidanceEntries(ctx context.Context, rows []gemara.GuidanceEntryRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin guidance entries tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO guidance_entries (catalog_id, guideline_id, title, objective, group_id, state, applicability)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (catalog_id, guideline_id) DO UPDATE SET
		  title = EXCLUDED.title,
		  objective = EXCLUDED.objective,
		  group_id = EXCLUDED.group_id,
		  state = EXCLUDED.state,
		  applicability = EXCLUDED.applicability,
		  imported_at = now()`
	for _, r := range rows {
		app := r.Applicability
		if app == nil {
			app = []string{}
		}
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.GuidelineID, r.Title, r.Objective, r.GroupID, r.State, app,
		); err != nil {
			return fmt.Errorf("insert guidance entry: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit guidance entries: %w", err)
	}
	return nil
}

func (s *Store) CountControls(ctx context.Context, catalogID string) (int, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM controls WHERE catalog_id = $1`, catalogID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count controls: %w", err)
	}
	return int(count), nil
}

func (s *Store) InsertThreats(ctx context.Context, rows []gemara.ThreatRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin threats tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO threats (catalog_id, threat_id, title, description, group_id, policy_id) VALUES ($1, $2, $3, $4, $5, $6)`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.ThreatID, r.Title, r.Description, r.GroupID, r.PolicyID,
		); err != nil {
			return fmt.Errorf("insert threat: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit threats: %w", err)
	}
	return nil
}

func (s *Store) CountThreats(ctx context.Context, catalogID string) (int, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM threats WHERE catalog_id = $1`, catalogID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count threats: %w", err)
	}
	return int(count), nil
}

func (s *Store) QueryThreats(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.ThreatRow, error) {
	qb := psql.Select("catalog_id", "threat_id", "title", "description", "group_id", "policy_id").
		From("threats").
		OrderBy("catalog_id", "threat_id").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if catalogID != "" {
		qb = qb.Where(sq.Eq{"catalog_id": catalogID})
	}
	if policyID != "" {
		qb = qb.Where(sq.Eq{"policy_id": policyID})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query threats: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query threats: %w", err)
	}
	defer rows.Close()

	var out []gemara.ThreatRow
	for rows.Next() {
		var r gemara.ThreatRow
		if err := rows.Scan(&r.CatalogID, &r.ThreatID, &r.Title, &r.Description, &r.GroupID, &r.PolicyID); err != nil {
			return nil, fmt.Errorf("scan threat: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) QueryControlThreats(ctx context.Context, catalogID, controlID string, limit int) ([]gemara.ControlThreatRow, error) {
	qb := psql.Select("catalog_id", "control_id", "threat_reference_id", "threat_entry_id").
		From("control_threats").
		OrderBy("catalog_id", "control_id", "threat_reference_id").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if catalogID != "" {
		qb = qb.Where(sq.Eq{"catalog_id": catalogID})
	}
	if controlID != "" {
		qb = qb.Where(sq.Eq{"control_id": controlID})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query control threats: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query control threats: %w", err)
	}
	defer rows.Close()

	var out []gemara.ControlThreatRow
	for rows.Next() {
		var r gemara.ControlThreatRow
		if err := rows.Scan(&r.CatalogID, &r.ControlID, &r.ThreatReferenceID, &r.ThreatEntryID); err != nil {
			return nil, fmt.Errorf("scan control threat: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InsertRisks(ctx context.Context, rows []gemara.RiskRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin risks tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO risks (catalog_id, risk_id, title, description, severity, group_id, impact, policy_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.RiskID, r.Title, r.Description, r.Severity, r.GroupID, r.Impact, r.PolicyID,
		); err != nil {
			return fmt.Errorf("insert risk: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit risks: %w", err)
	}
	return nil
}

func (s *Store) InsertRiskThreats(ctx context.Context, rows []gemara.RiskThreatRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin risk threats tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO risk_threats (catalog_id, risk_id, threat_reference_id, threat_entry_id) VALUES ($1, $2, $3, $4)`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.CatalogID, r.RiskID, r.ThreatReferenceID, r.ThreatEntryID,
		); err != nil {
			return fmt.Errorf("insert risk threat: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit risk threats: %w", err)
	}
	return nil
}

func (s *Store) CountRisks(ctx context.Context, catalogID string) (int, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM risks WHERE catalog_id = $1`, catalogID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count risks: %w", err)
	}
	return int(count), nil
}

func (s *Store) QueryRisks(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.RiskRow, error) {
	qb := psql.Select("catalog_id", "risk_id", "title", "description", "severity", "group_id", "impact", "policy_id").
		From("risks").
		OrderBy("catalog_id", "risk_id").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if catalogID != "" {
		qb = qb.Where(sq.Eq{"catalog_id": catalogID})
	}
	if policyID != "" {
		qb = qb.Where(sq.Eq{"policy_id": policyID})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query risks: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query risks: %w", err)
	}
	defer rows.Close()

	var out []gemara.RiskRow
	for rows.Next() {
		var r gemara.RiskRow
		if err := rows.Scan(&r.CatalogID, &r.RiskID, &r.Title, &r.Description, &r.Severity, &r.GroupID, &r.Impact, &r.PolicyID); err != nil {
			return nil, fmt.Errorf("scan risk: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) QueryRiskThreats(ctx context.Context, catalogID, riskID string, limit int) ([]gemara.RiskThreatRow, error) {
	qb := psql.Select("catalog_id", "risk_id", "threat_reference_id", "threat_entry_id").
		From("risk_threats").
		OrderBy("catalog_id", "risk_id", "threat_reference_id").
		Limit(uint64(consts.ClampLimit(limit))) //nolint:gosec // G115: clamped positive
	if catalogID != "" {
		qb = qb.Where(sq.Eq{"catalog_id": catalogID})
	}
	if riskID != "" {
		qb = qb.Where(sq.Eq{"risk_id": riskID})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query risk threats: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query risk threats: %w", err)
	}
	defer rows.Close()

	var out []gemara.RiskThreatRow
	for rows.Next() {
		var r gemara.RiskThreatRow
		if err := rows.Scan(&r.CatalogID, &r.RiskID, &r.ThreatReferenceID, &r.ThreatEntryID); err != nil {
			return nil, fmt.Errorf("scan risk threat: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
