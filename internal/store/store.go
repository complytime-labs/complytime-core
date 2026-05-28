// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/complytime-labs/complytime-core/internal/gemara"
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
