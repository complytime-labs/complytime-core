// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// PolicyStore defines read/write operations for policy artifacts.
type PolicyStore interface {
	InsertPolicy(ctx context.Context, p Policy) error
	ListPolicies(ctx context.Context) ([]Policy, error)
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
}

// MappingStore defines read/write operations for crosswalk mappings.
type MappingStore interface {
	InsertMapping(ctx context.Context, m MappingDocument) error
	ListMappings(ctx context.Context, policyID string) ([]MappingDocument, error)
	ListAllMappings(ctx context.Context) ([]MappingDocument, error)
	QueryMappings(ctx context.Context, sourceCatalogID, targetCatalogID string, limit int) ([]gemara.MappingEntry, error)
	InsertMappingEntries(ctx context.Context, entries []gemara.MappingEntry) error
	DeleteMappingEntries(ctx context.Context, sourceCatalogID, targetCatalogID string) error
	CountMappingEntries(ctx context.Context, mappingID string) (int, error)
}

// GuidanceStore defines write operations for parsed guidance catalog entries.
type GuidanceStore interface {
	InsertGuidanceEntries(ctx context.Context, rows []gemara.GuidanceEntryRow) error
}

// TesseraAppender defines operations for appending entries to a transparency log.
type TesseraAppender interface {
	Add(ctx context.Context, entry []byte) (uint64, error)
}

// ControlStore defines read/write operations for parsed control catalog entries.
type ControlStore interface {
	InsertControls(ctx context.Context, rows []gemara.ControlRow) error
	InsertAssessmentRequirements(ctx context.Context, rows []gemara.AssessmentRequirementRow) error
	InsertControlThreats(ctx context.Context, rows []gemara.ControlThreatRow) error
	CountControls(ctx context.Context, catalogID string) (int, error)
}

// ThreatStore defines read/write operations for parsed threat catalog entries.
type ThreatStore interface {
	InsertThreats(ctx context.Context, rows []gemara.ThreatRow) error
	CountThreats(ctx context.Context, catalogID string) (int, error)
	QueryThreats(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.ThreatRow, error)
	QueryControlThreats(ctx context.Context, catalogID, controlID string, limit int) ([]gemara.ControlThreatRow, error)
}

// RiskStore defines read/write operations for parsed risk catalog entries.
type RiskStore interface {
	InsertRisks(ctx context.Context, rows []gemara.RiskRow) error
	InsertRiskThreats(ctx context.Context, rows []gemara.RiskThreatRow) error
	CountRisks(ctx context.Context, catalogID string) (int, error)
	QueryRisks(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.RiskRow, error)
	QueryRiskThreats(ctx context.Context, catalogID, riskID string, limit int) ([]gemara.RiskThreatRow, error)
}

// CatalogStore defines read/write operations for raw catalog artifacts.
type CatalogStore interface {
	InsertCatalog(ctx context.Context, c Catalog) error
	ListCatalogs(ctx context.Context) ([]Catalog, error)
	GetCatalog(ctx context.Context, catalogID string) (*Catalog, error)
}

// EvidenceStore defines read/write operations for evidence records.
type EvidenceStore interface {
	InsertEvidence(ctx context.Context, records []EvidenceRecord) (int, error)
	QueryEvidence(ctx context.Context, f EvidenceFilter) ([]EvidenceRecord, error)
}

// AuditLogStore defines read/write operations for audit log artifacts.
type AuditLogStore interface {
	InsertAuditLog(ctx context.Context, a AuditLog) error
	ListAuditLogs(ctx context.Context, policyID string, start, end time.Time, limit int) ([]AuditLog, error)
	GetAuditLog(ctx context.Context, auditID string) (*AuditLog, error)
}

// EvidenceAssessmentStore defines write operations for agent-produced classifications.
type EvidenceAssessmentStore interface {
	InsertEvidenceAssessments(ctx context.Context, assessments []EvidenceAssessment) error
}

// CertificationStore defines read/write operations for evidence certifications.
type CertificationStore interface {
	InsertCertifications(ctx context.Context, rows []CertificationRow) error
	UpdateEvidenceCertified(ctx context.Context, evidenceID string, certified bool) error
	QueryCertifications(ctx context.Context, evidenceID string) ([]CertificationRow, error)
	QueryRecentEvidence(
		ctx context.Context, policyID string, since time.Time,
	) ([]EvidenceRowLite, error)
}

// RequirementStore defines read operations for the requirement matrix.
type RequirementStore interface {
	ListRequirementMatrix(ctx context.Context, f RequirementFilter) ([]RequirementRow, error)
	ListRequirementEvidence(ctx context.Context, requirementID string, f RequirementFilter) ([]RequirementEvidenceRow, error)
}

// DraftAuditLogStore defines operations for agent-produced draft audit logs
// that require human review before promotion to the official audit_logs table.
type DraftAuditLogStore interface {
	InsertDraftAuditLog(ctx context.Context, d DraftAuditLog) error
	ListDraftAuditLogs(ctx context.Context, status string, limit int) ([]DraftAuditLog, error)
	GetDraftAuditLog(ctx context.Context, draftID string) (*DraftAuditLog, error)
	UpdateDraftEdits(ctx context.Context, draftID string, reviewerEdits string) error
	PromoteDraftAuditLog(ctx context.Context, draftID string, reviewedBy string) error
}

// BundleArtifactRow represents an artifact within an OCI bundle.
type BundleArtifactRow struct {
	BundleID        string
	TesseraLogIndex uint64
	ArtifactType    string
	ArtifactID      string
	OCIReference    string
}

// TargetStore defines operations for target registrations.
type TargetStore interface {
	InsertTarget(ctx context.Context, t TargetRow) error
	GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*TargetRow, error)
	ListTargets(ctx context.Context) ([]TargetRow, error)
}

// Store provides typed access to PostgreSQL tables for policies,
// mapping documents, evidence, and audit logs. Implements all
// domain store interfaces.
type Store struct {
	pool *pgxpool.Pool
}

// Compile-time interface satisfaction checks.
var (
	_ PolicyStore             = (*Store)(nil)
	_ MappingStore            = (*Store)(nil)
	_ EvidenceStore           = (*Store)(nil)
	_ AuditLogStore           = (*Store)(nil)
	_ ControlStore            = (*Store)(nil)
	_ ThreatStore             = (*Store)(nil)
	_ RiskStore               = (*Store)(nil)
	_ CatalogStore            = (*Store)(nil)
	_ EvidenceAssessmentStore = (*Store)(nil)
	_ DraftAuditLogStore      = (*Store)(nil)
	_ RequirementStore        = (*Store)(nil)
	_ CertificationStore      = (*Store)(nil)
	_ GuidanceStore           = (*Store)(nil)
	_ TargetStore             = (*Store)(nil)
	_ PolicyDimensionStore    = (*Store)(nil)
)

// New wraps a PostgreSQL connection pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

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
	Technologies         []string   `json:"technologies,omitempty"`
	Geopolitical         []string   `json:"geopolitical,omitempty"`
	Sensitivity          []string   `json:"sensitivity,omitempty"`
	Users                []string   `json:"users,omitempty"`
	Groups               []string   `json:"groups,omitempty"`
	EvaluationTimelineStart *time.Time `json:"evaluation_timeline_start,omitempty"`
	EvaluationTimelineEnd   *time.Time `json:"evaluation_timeline_end,omitempty"`
	BundleID             string     `json:"bundle_id,omitempty"`
	TesseraLogIndex      *uint64    `json:"tessera_log_index,omitempty"`
}

// TargetRow represents a target registration with dimensional metadata.
type TargetRow struct {
	TargetID        string    `json:"target_id"`
	TesseraLogIndex uint64    `json:"tessera_log_index"`
	TargetName      string    `json:"target_name"`
	TargetType      string    `json:"target_type"`
	Technologies    []string  `json:"technologies"`
	Geopolitical    []string  `json:"geopolitical"`
	Sensitivity     []string  `json:"sensitivity"`
	Users           []string  `json:"users"`
	Groups          []string  `json:"groups"`
	RegisteredAt    time.Time `json:"registered_at"`
	RegisteredBy    string    `json:"registered_by"`
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

// MappingDocument represents a global crosswalk mapping artifact.
type MappingDocument struct {
	MappingID       string    `json:"mapping_id"`
	SourceCatalogID string    `json:"source_catalog_id"`
	TargetCatalogID string    `json:"target_catalog_id"`
	Framework       string    `json:"framework"`
	Content         string    `json:"content"`
	ImportedAt      time.Time `json:"imported_at"`
}

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
		Limit(uint64(consts.ClampLimit(limit)))
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
		Limit(uint64(consts.ClampLimit(limit)))
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
		Limit(uint64(consts.ClampLimit(limit)))
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
		Limit(uint64(consts.ClampLimit(limit)))
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


// EvidenceRecord represents a single evidence row for the REST API.
// Fields align with evidence-semconv-alignment.md; new fields use omitempty
// for backward compatibility with minimal payloads.
type EvidenceRecord struct {
	EvidenceID string `json:"evidence_id"`
	PolicyID   string `json:"policy_id"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TargetEnv  string `json:"target_env,omitempty"`

	EngineName    string `json:"engine_name,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	RuleID        string `json:"rule_id"`
	RuleName      string `json:"rule_name,omitempty"`
	RuleURI       string `json:"rule_uri,omitempty"`

	EvalResult  string `json:"eval_result"`
	EvalMessage string `json:"eval_message,omitempty"`

	ControlID            string   `json:"control_id"`
	ControlCatalogID     string   `json:"control_catalog_id,omitempty"`
	ControlCategory      string   `json:"control_category,omitempty"`
	ControlApplicability []string `json:"control_applicability,omitempty"`
	RequirementID        string   `json:"requirement_id,omitempty"`
	PlanID               string   `json:"plan_id,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	StepsExecuted        int      `json:"steps_executed,omitempty"`
	ComplianceStatus     string   `json:"compliance_status,omitempty"`
	RiskLevel            string   `json:"risk_level,omitempty"`
	Frameworks           []string `json:"frameworks,omitempty"`
	Requirements         []string `json:"requirements,omitempty"`

	RemediationAction string `json:"remediation_action,omitempty"`
	RemediationStatus string `json:"remediation_status,omitempty"`
	RemediationDesc   string `json:"remediation_desc,omitempty"`
	ExceptionID       string `json:"exception_id,omitempty"`
	ExceptionActive   *bool  `json:"exception_active,omitempty"`

	EnrichmentStatus string `json:"enrichment_status,omitempty"`

	AttestationRef string `json:"attestation_ref,omitempty"`
	SourceRegistry string `json:"source_registry,omitempty"`
	BlobRef        string `json:"blob_ref,omitempty"`

	Certified bool `json:"certified"`

	Owner          string    `json:"owner,omitempty"`
	CollectedAt    time.Time `json:"collected_at"`
	Classification string    `json:"classification,omitempty"`
	LogIndex       *uint64   `json:"log_index,omitempty"` // Tessera transparency log position

	// Publisher identity from JWT verification
	PublisherIssuer string `json:"publisher_issuer,omitempty"` // JWT iss claim
	SubmittedBy     string `json:"submitted_by,omitempty"`     // JWT sub claim
	PublisherType   string `json:"publisher_type,omitempty"`   // pipeline, service, or unknown
}

// nullStr returns nil for empty strings, pointer otherwise.
func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nullUint16 returns nil for zero, pointer otherwise.
func nullUint16(v int) *uint16 {
	if v <= 0 {
		return nil
	}
	u := uint16(v)
	return &u
}

// warnEvalMessageIfLarge logs when eval_message may be raw or embedded data
// rather than a short summary (see consts.EvalMessageWarnBytes).
func warnEvalMessageIfLarge(r EvidenceRecord) {
	if len(r.EvalMessage) <= consts.EvalMessageWarnBytes {
		return
	}
	slog.Warn("evidence eval_message exceeds recommended summary size",
		"bytes", len(r.EvalMessage),
		"warn_threshold_bytes", consts.EvalMessageWarnBytes,
		"policy_id", r.PolicyID,
		"evidence_id", r.EvidenceID,
	)
}

// normalizeEvidence applies defaults to an EvidenceRecord before insert.
func normalizeEvidence(r *EvidenceRecord) {
	if r.EvidenceID == "" {
		r.EvidenceID = uuid.New().String()
	}
	if r.EnrichmentStatus == "" {
		r.EnrichmentStatus = "Success"
	}
	if r.ComplianceStatus == "" {
		r.ComplianceStatus = "Unknown"
	}
	if r.EvalResult == "" {
		r.EvalResult = "Unknown"
	}
	if r.ControlApplicability == nil {
		r.ControlApplicability = []string{}
	}
	if r.Requirements == nil {
		r.Requirements = []string{}
	}
}

// InsertEvidence batch-inserts evidence records with full semconv column coverage.
func (s *Store) InsertEvidence(ctx context.Context, records []EvidenceRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin evidence tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO evidence (
		evidence_id, target_id, target_name, target_type, target_env,
		engine_name, engine_version, rule_id, rule_name, rule_uri,
		eval_result, eval_message,
		policy_id, control_id, control_catalog_id, control_category,
		control_applicability, requirement_id, plan_id,
		confidence, steps_executed, compliance_status,
		risk_level, requirements,
		remediation_action, remediation_status, remediation_desc,
		exception_id, exception_active,
		enrichment_status,
		attestation_ref, source_registry, blob_ref,
		owner, collected_at, log_index,
		publisher_issuer, submitted_by, publisher_type
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)
	ON CONFLICT (evidence_id, control_id, requirement_id) DO UPDATE SET
		target_name = EXCLUDED.target_name,
		target_type = EXCLUDED.target_type,
		target_env = EXCLUDED.target_env,
		engine_name = EXCLUDED.engine_name,
		engine_version = EXCLUDED.engine_version,
		eval_result = EXCLUDED.eval_result,
		eval_message = EXCLUDED.eval_message,
		compliance_status = EXCLUDED.compliance_status,
		owner = EXCLUDED.owner,
		collected_at = EXCLUDED.collected_at,
		log_index = EXCLUDED.log_index,
		publisher_issuer = EXCLUDED.publisher_issuer,
		submitted_by = EXCLUDED.submitted_by,
		publisher_type = EXCLUDED.publisher_type`

	count := 0
	for _, r := range records {
		normalizeEvidence(&r)
		warnEvalMessageIfLarge(r)
		if _, err := tx.Exec(ctx, q,
			r.EvidenceID,
			r.TargetID, nullStr(r.TargetName), nullStr(r.TargetType), nullStr(r.TargetEnv),
			nullStr(r.EngineName), nullStr(r.EngineVersion), r.RuleID, nullStr(r.RuleName), nullStr(r.RuleURI),
			r.EvalResult, nullStr(r.EvalMessage),
			r.PolicyID, r.ControlID, nullStr(r.ControlCatalogID), nullStr(r.ControlCategory),
			r.ControlApplicability, r.RequirementID, nullStr(r.PlanID),
			nullStr(r.Confidence), nullUint16(r.StepsExecuted), r.ComplianceStatus,
			nullStr(r.RiskLevel), r.Requirements,
			nullStr(r.RemediationAction), nullStr(r.RemediationStatus), nullStr(r.RemediationDesc),
			nullStr(r.ExceptionID), r.ExceptionActive,
			r.EnrichmentStatus,
			nullStr(r.AttestationRef), nullStr(r.SourceRegistry), nullStr(r.BlobRef),
			nullStr(r.Owner), r.CollectedAt, r.LogIndex,
			nullStr(r.PublisherIssuer), nullStr(r.SubmittedBy), nullStr(r.PublisherType),
		); err != nil {
			return count, fmt.Errorf("insert evidence row: %w", err)
		}
		count++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit evidence: %w", err)
	}
	return count, nil
}

// EvidenceFilter holds query parameters for evidence queries.
type EvidenceFilter struct {
	PolicyIDs     []string
	ControlID     string
	TargetName    string
	TargetType    string
	TargetEnv     string
	EngineVersion string
	Owner         string
	Start         time.Time
	End           time.Time
	Limit         int
	Offset        int
}

// QueryEvidence returns evidence rows matching the filter.
func (s *Store) QueryEvidence(ctx context.Context, f EvidenceFilter) ([]EvidenceRecord, error) {
	qb := psql.Select(
		"e.evidence_id", "e.policy_id", "e.target_id",
		"COALESCE(e.target_name, '') AS target_name",
		"COALESCE(e.target_type, '') AS target_type",
		"COALESCE(e.target_env, '') AS target_env",
		"COALESCE(e.engine_name, '') AS engine_name",
		"COALESCE(e.engine_version, '') AS engine_version",
		"e.rule_id",
		"COALESCE(e.rule_name, '') AS rule_name",
		"e.eval_result",
		"COALESCE(e.eval_message, '') AS eval_message",
		"e.control_id",
		"COALESCE(e.control_catalog_id, '') AS control_catalog_id",
		"COALESCE(e.control_category, '') AS control_category",
		"e.requirement_id",
		"COALESCE(e.plan_id, '') AS plan_id",
		"COALESCE(e.confidence, '') AS confidence",
		"e.compliance_status",
		"COALESCE(e.risk_level, '') AS risk_level",
		"e.requirements",
		"e.enrichment_status",
		"COALESCE(e.attestation_ref, '') AS attestation_ref",
		"COALESCE(e.source_registry, '') AS source_registry",
		"COALESCE(e.blob_ref, '') AS blob_ref",
		"e.certified",
		"e.collected_at",
		"e.log_index",
		"COALESCE(ea_latest.classification, '') AS classification",
	).From(`evidence e
		LEFT JOIN LATERAL (
			SELECT ea2.classification
			FROM evidence_assessments ea2
			WHERE ea2.evidence_id = e.evidence_id
			ORDER BY ea2.assessed_at DESC
			LIMIT 1
		) AS ea_latest ON TRUE`).
		OrderBy("e.collected_at DESC")

	if len(f.PolicyIDs) == 1 {
		qb = qb.Where(sq.Eq{"e.policy_id": f.PolicyIDs[0]})
	} else if len(f.PolicyIDs) > 1 {
		qb = qb.Where(sq.Eq{"e.policy_id": f.PolicyIDs})
	}
	if f.ControlID != "" {
		qb = qb.Where(sq.Eq{"e.control_id": f.ControlID})
	}
	if f.TargetName != "" {
		qb = qb.Where(sq.Eq{"e.target_name": f.TargetName})
	}
	if f.TargetType != "" {
		qb = qb.Where(sq.Eq{"e.target_type": f.TargetType})
	}
	if f.TargetEnv != "" {
		qb = qb.Where(sq.Eq{"e.target_env": f.TargetEnv})
	}
	if f.EngineVersion != "" {
		qb = qb.Where(sq.Eq{"e.engine_version": f.EngineVersion})
	}
	if f.Owner != "" {
		qb = qb.Where(sq.Eq{"e.owner": f.Owner})
	}
	if !f.Start.IsZero() {
		qb = qb.Where(sq.GtOrEq{"e.collected_at": f.Start})
	}
	if !f.End.IsZero() {
		qb = qb.Where(sq.LtOrEq{"e.collected_at": f.End})
	}
	if f.Limit > 0 {
		qb = qb.Limit(uint64(f.Limit))
	}
	if f.Offset > 0 {
		qb = qb.Offset(uint64(f.Offset))
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query evidence: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	var out []EvidenceRecord
	for rows.Next() {
		var r EvidenceRecord
		if err := rows.Scan(
			&r.EvidenceID, &r.PolicyID, &r.TargetID,
			&r.TargetName, &r.TargetType, &r.TargetEnv,
			&r.EngineName, &r.EngineVersion,
			&r.RuleID, &r.RuleName,
			&r.EvalResult, &r.EvalMessage,
			&r.ControlID, &r.ControlCatalogID, &r.ControlCategory,
			&r.RequirementID, &r.PlanID,
			&r.Confidence, &r.ComplianceStatus,
			&r.RiskLevel, &r.Requirements,
			&r.EnrichmentStatus,
			&r.AttestationRef, &r.SourceRegistry, &r.BlobRef,
			&r.Certified,
			&r.CollectedAt,
			&r.LogIndex,
			&r.Classification,
		); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CertificationRow represents a single certification verdict.
type CertificationRow struct {
	EvidenceID       string    `json:"evidence_id"`
	Certifier        string    `json:"certifier"`
	CertifierVersion string    `json:"certifier_version"`
	Result           string    `json:"result"`
	Reason           string    `json:"reason"`
	CertifiedAt      time.Time `json:"certified_at,omitempty"`
}

// EvidenceRowLite is a lightweight evidence projection for the certifier pipeline.
type EvidenceRowLite struct {
	EvidenceID       string    `json:"evidence_id"`
	TargetID         string    `json:"target_id"`
	RuleID           string    `json:"rule_id"`
	EvalResult       string    `json:"eval_result"`
	ComplianceStatus string    `json:"compliance_status"`
	EngineName       string    `json:"engine_name"`
	SourceRegistry   string    `json:"source_registry"`
	AttestationRef   string    `json:"attestation_ref"`
	EnrichmentStatus string    `json:"enrichment_status"`
	CollectedAt      time.Time `json:"collected_at"`
}

// InsertCertifications batch-inserts certification verdicts.
func (s *Store) InsertCertifications(ctx context.Context, rows []CertificationRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin certifications tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO certifications (evidence_id, certifier, certifier_version, result, reason, certified_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (evidence_id, certifier)
DO UPDATE SET certifier_version = EXCLUDED.certifier_version,
             result = EXCLUDED.result,
             reason = EXCLUDED.reason,
             certified_at = EXCLUDED.certified_at`
	for _, r := range rows {
		if _, err := tx.Exec(ctx, q,
			r.EvidenceID, r.Certifier, r.CertifierVersion,
			r.Result, r.Reason,
		); err != nil {
			return fmt.Errorf("insert certification: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit certifications: %w", err)
	}
	return nil
}

// UpdateEvidenceCertified sets the denormalized certified flag on an evidence row.
func (s *Store) UpdateEvidenceCertified(
	ctx context.Context, evidenceID string, certified bool,
) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE evidence SET certified = $1 WHERE evidence_id = $2`,
		certified, evidenceID)
	return err
}

// QueryCertifications returns certification verdicts for a given evidence row.
func (s *Store) QueryCertifications(
	ctx context.Context, evidenceID string,
) ([]CertificationRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT evidence_id, certifier, certifier_version, result, reason, certified_at
		 FROM certifications WHERE evidence_id = $1 ORDER BY certified_at DESC`, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("query certifications: %w", err)
	}
	defer rows.Close()

	var out []CertificationRow
	for rows.Next() {
		var r CertificationRow
		if err := rows.Scan(
			&r.EvidenceID, &r.Certifier, &r.CertifierVersion,
			&r.Result, &r.Reason, &r.CertifiedAt,
		); err != nil {
			return nil, fmt.Errorf("scan certification: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QueryRecentEvidence returns lightweight evidence rows for a policy ingested after since.
func (s *Store) QueryRecentEvidence(
	ctx context.Context, policyID string, since time.Time,
) ([]EvidenceRowLite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT evidence_id, target_id, rule_id, eval_result, compliance_status,
			COALESCE(engine_name, '') AS engine_name,
			COALESCE(source_registry, '') AS source_registry,
			COALESCE(attestation_ref, '') AS attestation_ref,
			enrichment_status, collected_at
		 FROM evidence
		 WHERE policy_id = $1 AND ingested_at >= $2
		 ORDER BY ingested_at DESC`, policyID, since)
	if err != nil {
		return nil, fmt.Errorf("query recent evidence: %w", err)
	}
	defer rows.Close()

	var out []EvidenceRowLite
	for rows.Next() {
		var r EvidenceRowLite
		if err := rows.Scan(
			&r.EvidenceID, &r.TargetID, &r.RuleID, &r.EvalResult,
			&r.ComplianceStatus, &r.EngineName, &r.SourceRegistry,
			&r.AttestationRef, &r.EnrichmentStatus, &r.CollectedAt,
		); err != nil {
			return nil, fmt.Errorf("scan recent evidence: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditLog represents a stored audit log artifact.
type AuditLog struct {
	AuditID       string    `json:"audit_id"`
	PolicyID      string    `json:"policy_id"`
	AuditStart    time.Time `json:"audit_start"`
	AuditEnd      time.Time `json:"audit_end"`
	Framework     string    `json:"framework,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
	Content       string    `json:"content"`
	Summary       string    `json:"summary"`
	Model         string    `json:"model,omitempty"`
	PromptVersion string    `json:"prompt_version,omitempty"`
}

// InsertAuditLog stores an AuditLog artifact.
func (s *Store) InsertAuditLog(ctx context.Context, a AuditLog) error {
	if a.AuditID == "" {
		a.AuditID = uuid.New().String()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_logs (audit_id, policy_id, audit_start, audit_end, framework, created_by, content, summary, model, prompt_version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.AuditID, a.PolicyID, a.AuditStart, a.AuditEnd, a.Framework, a.CreatedBy, a.Content, a.Summary, a.Model, a.PromptVersion,
	)
	return err
}

// ListAuditLogs returns audit logs for a given policy, optionally filtered by time range.
func (s *Store) ListAuditLogs(ctx context.Context, policyID string, start, end time.Time, limit int) ([]AuditLog, error) {
	qb := psql.Select("audit_id", "policy_id", "audit_start", "audit_end", "framework",
		"created_at", "created_by", "summary", "model", "prompt_version").
		From("audit_logs").
		Where(sq.Eq{"policy_id": policyID}).
		OrderBy("audit_start DESC").
		Limit(uint64(consts.ClampLimit(limit)))
	if !start.IsZero() {
		qb = qb.Where(sq.GtOrEq{"audit_start": start})
	}
	if !end.IsZero() {
		qb = qb.Where(sq.LtOrEq{"audit_end": end})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list audit logs: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.AuditID, &a.PolicyID, &a.AuditStart, &a.AuditEnd, &a.Framework, &a.CreatedAt, &a.CreatedBy, &a.Summary, &a.Model, &a.PromptVersion); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAuditLog returns a single audit log with full content.
func (s *Store) GetAuditLog(ctx context.Context, auditID string) (*AuditLog, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT audit_id, policy_id, audit_start, audit_end, framework, created_at, created_by, content, summary, model, prompt_version FROM audit_logs WHERE audit_id = $1`, auditID)
	var a AuditLog
	if err := row.Scan(&a.AuditID, &a.PolicyID, &a.AuditStart, &a.AuditEnd, &a.Framework, &a.CreatedAt, &a.CreatedBy, &a.Content, &a.Summary, &a.Model, &a.PromptVersion); err != nil {
		return nil, fmt.Errorf("get audit log: %w", err)
	}
	return &a, nil
}

// EvidenceAssessment represents an agent-produced classification for an evidence row.
type EvidenceAssessment struct {
	EvidenceID     string    `json:"evidence_id"`
	PolicyID       string    `json:"policy_id"`
	PlanID         string    `json:"plan_id"`
	Classification string    `json:"classification"`
	Reason         string    `json:"reason"`
	AssessedAt     time.Time `json:"assessed_at"`
	AssessedBy     string    `json:"assessed_by"`
}

// ErrRequirementNotFound is returned by ListRequirementEvidence when the
// requirement ID is not known for the policy (no matching catalog row and no
// evidence rows scoped to that ID).
var ErrRequirementNotFound = errors.New("requirement not found")
var ErrDraftAlreadyPromoted = errors.New("draft already promoted")
var ErrDraftNotFound = errors.New("draft not found")

// ValidClassifications enumerates the allowed 7-state classification values.
var ValidClassifications = map[string]bool{
	"Healthy":        true,
	"Failing":        true,
	"Wrong Source":   true,
	"Wrong Method":   true,
	"Unfit Evidence": true,
	"Stale":          true,
	"No Evidence":    true,
}

// InsertEvidenceAssessments batch-inserts agent classifications.
func (s *Store) InsertEvidenceAssessments(ctx context.Context, assessments []EvidenceAssessment) error {
	if len(assessments) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin evidence assessments tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `INSERT INTO evidence_assessments (evidence_id, policy_id, plan_id, classification, reason, assessed_at, assessed_by) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	for _, a := range assessments {
		if _, err := tx.Exec(ctx, q, a.EvidenceID, a.PolicyID, a.PlanID, a.Classification, a.Reason, a.AssessedAt, a.AssessedBy); err != nil {
			return fmt.Errorf("insert evidence assessment: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit evidence assessments: %w", err)
	}
	return nil
}

// Catalog represents a stored catalog artifact (ControlCatalog, ThreatCatalog, etc.).
type Catalog struct {
	CatalogID   string    `json:"catalog_id"`
	CatalogType string    `json:"catalog_type"`
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	PolicyID    string    `json:"policy_id,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
}

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

// DraftAuditLog represents an agent-produced audit log awaiting human review.
type DraftAuditLog struct {
	DraftID        string     `json:"draft_id"`
	PolicyID       string     `json:"policy_id"`
	AuditStart     time.Time  `json:"audit_start"`
	AuditEnd       time.Time  `json:"audit_end"`
	Framework      string     `json:"framework,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	Status         string     `json:"status"`
	Content        string     `json:"content"`
	Summary        string     `json:"summary"`
	AgentReasoning string     `json:"agent_reasoning,omitempty"`
	Model          string     `json:"model,omitempty"`
	PromptVersion  string     `json:"prompt_version,omitempty"`
	ReviewedBy     *string    `json:"reviewed_by,omitempty"`
	PromotedAt     *time.Time `json:"promoted_at,omitempty"`
	ReviewerEdits  string     `json:"reviewer_edits,omitempty"`
}

// InsertDraftAuditLog stores an agent-produced draft.
func (s *Store) InsertDraftAuditLog(ctx context.Context, d DraftAuditLog) error {
	if d.DraftID == "" {
		d.DraftID = uuid.New().String()
	}
	if d.Status == "" {
		d.Status = "pending_review"
	}
	edits := d.ReviewerEdits
	if edits == "" {
		edits = "{}"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO draft_audit_logs (draft_id, policy_id, audit_start, audit_end, framework, status, content, summary, agent_reasoning, model, prompt_version, reviewer_edits) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		d.DraftID, d.PolicyID, d.AuditStart, d.AuditEnd, d.Framework, d.Status, d.Content, d.Summary, d.AgentReasoning, d.Model, d.PromptVersion, edits,
	)
	return err
}

// ListDraftAuditLogs returns drafts filtered by status. Empty status returns all.
func (s *Store) ListDraftAuditLogs(ctx context.Context, status string, limit int) ([]DraftAuditLog, error) {
	qb := psql.Select("draft_id", "policy_id", "audit_start", "audit_end", "framework",
		"created_at", "status", "summary", "agent_reasoning", "model", "prompt_version",
		"reviewed_by", "promoted_at", "reviewer_edits").
		From("draft_audit_logs").
		OrderBy("created_at DESC").
		Limit(uint64(consts.ClampLimit(limit)))
	if status != "" {
		qb = qb.Where(sq.Eq{"status": status})
	}

	query, args, err := qb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list draft audit logs: %w", err)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list draft audit logs: %w", err)
	}
	defer rows.Close()

	var out []DraftAuditLog
	for rows.Next() {
		var d DraftAuditLog
		if err := rows.Scan(&d.DraftID, &d.PolicyID, &d.AuditStart, &d.AuditEnd, &d.Framework, &d.CreatedAt, &d.Status, &d.Summary, &d.AgentReasoning, &d.Model, &d.PromptVersion, &d.ReviewedBy, &d.PromotedAt, &d.ReviewerEdits); err != nil {
			return nil, fmt.Errorf("scan draft audit log: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDraftAuditLog returns a single draft with full content.
func (s *Store) GetDraftAuditLog(ctx context.Context, draftID string) (*DraftAuditLog, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT draft_id, policy_id, audit_start, audit_end, framework, created_at, status, content, summary, agent_reasoning, model, prompt_version, reviewed_by, promoted_at, reviewer_edits FROM draft_audit_logs WHERE draft_id = $1`, draftID)
	var d DraftAuditLog
	if err := row.Scan(&d.DraftID, &d.PolicyID, &d.AuditStart, &d.AuditEnd, &d.Framework, &d.CreatedAt, &d.Status, &d.Content, &d.Summary, &d.AgentReasoning, &d.Model, &d.PromptVersion, &d.ReviewedBy, &d.PromotedAt, &d.ReviewerEdits); err != nil {
		return nil, fmt.Errorf("get draft audit log: %w", err)
	}
	return &d, nil
}

// UpdateDraftEdits persists reviewer edits (type overrides, notes) on a pending draft.
func (s *Store) UpdateDraftEdits(ctx context.Context, draftID string, reviewerEdits string) error {
	draft, err := s.GetDraftAuditLog(ctx, draftID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, draftID)
	}
	if draft.Status != "pending_review" {
		return ErrDraftAlreadyPromoted
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE draft_audit_logs SET reviewer_edits = $1 WHERE draft_id = $2 AND status = 'pending_review'`,
		reviewerEdits, draftID)
	return err
}

// PromoteDraftAuditLog copies a draft to the official audit_logs table and marks it promoted.
func (s *Store) PromoteDraftAuditLog(ctx context.Context, draftID string, reviewedBy string) error {
	draft, err := s.GetDraftAuditLog(ctx, draftID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, draftID)
	}
	if draft.Status == "promoted" {
		return ErrDraftAlreadyPromoted
	}

	mergedContent, err := mergeReviewerEdits(draft.Content, draft.ReviewerEdits)
	if err != nil {
		slog.Warn("reviewer edits merge failed, using original content", "draft_id", draftID, "error", err)
		mergedContent = draft.Content
	}

	official := AuditLog{
		AuditID:       uuid.New().String(),
		PolicyID:      draft.PolicyID,
		AuditStart:    draft.AuditStart,
		AuditEnd:      draft.AuditEnd,
		Framework:     draft.Framework,
		CreatedBy:     reviewedBy,
		Content:       mergedContent,
		Summary:       draft.Summary,
		Model:         draft.Model,
		PromptVersion: draft.PromptVersion,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin promote draft: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_logs (audit_id, policy_id, audit_start, audit_end, framework, created_by, content, summary, model, prompt_version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		official.AuditID, official.PolicyID, official.AuditStart, official.AuditEnd, official.Framework, official.CreatedBy, official.Content, official.Summary, official.Model, official.PromptVersion,
	); err != nil {
		return fmt.Errorf("insert promoted audit log: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE draft_audit_logs SET status = $1, reviewed_by = $2, promoted_at = now() WHERE draft_id = $3`,
		"promoted", reviewedBy, draft.DraftID,
	); err != nil {
		return fmt.Errorf("mark draft promoted: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit promote draft: %w", err)
	}
	return nil
}

// RequirementFilter holds query parameters for requirement matrix and evidence APIs.
type RequirementFilter struct {
	PolicyID       string
	Start          time.Time
	End            time.Time
	ControlFamily  string
	Classification string
	Limit          int
	Offset         int
}

// RequirementRow is a single row in the requirement matrix.
type RequirementRow struct {
	CatalogID       string `json:"catalog_id"`
	ControlID       string `json:"control_id"`
	ControlTitle    string `json:"control_title"`
	RequirementID   string `json:"requirement_id"`
	RequirementText string `json:"requirement_text"`
	EvidenceCount   uint64 `json:"evidence_count"`
	LatestEvidence  string `json:"latest_evidence,omitempty"`
	Classification  string `json:"classification,omitempty"`
}

// RequirementEvidenceRow is an evidence row returned in requirement drill-down.
type RequirementEvidenceRow struct {
	EvidenceID     string `json:"evidence_id"`
	TargetID       string `json:"target_id"`
	TargetName     string `json:"target_name,omitempty"`
	RuleID         string `json:"rule_id"`
	EvalResult     string `json:"eval_result"`
	Classification string `json:"classification,omitempty"`
	AssessedAt     string `json:"assessed_at,omitempty"`
	CollectedAt    string `json:"collected_at"`
	SourceRegistry string `json:"source_registry,omitempty"`
}

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

func (s *Store) InsertBundleArtifact(ctx context.Context, b BundleArtifactRow) error {
	const q = `INSERT INTO bundle_artifacts (bundle_id, tessera_log_index, artifact_type, artifact_id, oci_reference)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (bundle_id, tessera_log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q, b.BundleID, b.TesseraLogIndex, b.ArtifactType, b.ArtifactID, nullStr(b.OCIReference))
	if err != nil {
		return fmt.Errorf("insert bundle artifact: %w", err)
	}
	return nil
}

func (s *Store) InsertTarget(ctx context.Context, t TargetRow) error {
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

func (s *Store) GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*TargetRow, error) {
	const q = `SELECT target_id, tessera_log_index, target_name, target_type,
		technologies, geopolitical, sensitivity, users, groups,
		registered_at, registered_by
	FROM targets
	WHERE target_id = $1 AND registered_at <= $2
	ORDER BY registered_at DESC
	LIMIT 1`

	var t TargetRow
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

func (s *Store) ListTargets(ctx context.Context) ([]TargetRow, error) {
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

	var out []TargetRow
	for rows.Next() {
		var t TargetRow
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
			p.LogIndex = uint64(*logIndex)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// WitnessEvidenceRow contains publisher and certification data for witness verification.
type WitnessEvidenceRow struct {
	Certified       bool
	PublisherIssuer string
	SubmittedBy     string
	PublisherType   string
}

// QueryEvidenceByLogIndex retrieves certification and publisher data for a given Tessera log index.
// Returns nil if the evidence is not yet in PostgreSQL (async processing delay).
func (s *Store) QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*WitnessEvidenceRow, error) {
	const q = `SELECT certified, publisher_issuer, submitted_by, publisher_type
	           FROM evidence
	           WHERE log_index = $1
	           LIMIT 1`

	var row WitnessEvidenceRow
	err := s.pool.QueryRow(ctx, q, logIndex).Scan(&row.Certified, &row.PublisherIssuer, &row.SubmittedBy, &row.PublisherType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query evidence by log_index: %w", err)
	}

	return &row, nil
}

// IsIndexWitnessed checks if a Tessera log index has been verified and countersigned by the witness.
func (s *Store) IsIndexWitnessed(ctx context.Context, index uint64) bool {
	const q = `SELECT EXISTS(SELECT 1 FROM witnessed_indices WHERE log_index = $1)`

	var exists bool
	err := s.pool.QueryRow(ctx, q, index).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
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

// MarkIndexWitnessed records that a Tessera log index has been verified and countersigned.
func (s *Store) MarkIndexWitnessed(ctx context.Context, index uint64, witnessName, checkpointHash string) error {
	const q = `INSERT INTO witnessed_indices (log_index, witness_name, checkpoint_hash)
	           VALUES ($1, $2, $3)
	           ON CONFLICT (log_index) DO NOTHING`

	_, err := s.pool.Exec(ctx, q, index, witnessName, checkpointHash)
	if err != nil {
		return fmt.Errorf("mark index witnessed: %w", err)
	}
	return nil
}
