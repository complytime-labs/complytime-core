// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/complytime-labs/complytime-core/internal/audit"
	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/blob"
	"github.com/complytime-labs/complytime-core/internal/certify"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/posture"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// ── Type aliases for backward compatibility ─────────────────────────────────
// These let existing code (tests, e2e, cmd/) continue using store.XxxType
// without changing every single reference in one step.

type Policy = requirements.Policy
type MappingDocument = requirements.MappingDocument
type Catalog = requirements.Catalog
type TargetRow = requirements.TargetRow
type BundleArtifactRow = requirements.BundleArtifactRow
type DimensionQuery = requirements.DimensionQuery
type PolicyWithDimensions = requirements.PolicyWithDimensions
type PolicyQueryResponse = requirements.PolicyQueryResponse
type TargetSummary = requirements.TargetSummary
type OciImportedArtifact = requirements.OciImportedArtifact

type EvidenceRecord = evidence.EvidenceRecord
type EvidenceFilter = evidence.EvidenceFilter
type CertificationRow = evidence.CertificationRow
type EvidenceRowLite = evidence.EvidenceRowLite
type WitnessEvidenceRow = evidence.WitnessEvidenceRow

type AuditLog = audit.AuditLog
type DraftAuditLog = audit.DraftAuditLog
type EvidenceAssessment = audit.EvidenceAssessment

type RequirementFilter = posture.RequirementFilter
type RequirementRow = posture.RequirementRow
type RequirementEvidenceRow = posture.RequirementEvidenceRow
type InventoryItem = posture.InventoryItem
type InventoryFilter = posture.InventoryFilter

type TrustSignalRow = certify.TrustSignalRow

// ── Interface aliases ───────────────────────────────────────────────────────

type PolicyStore = requirements.PolicyStore
type MappingStore = requirements.MappingStore
type CatalogStore = requirements.CatalogStore
type ControlStore = requirements.ControlStore
type ThreatStore = requirements.ThreatStore
type RiskStore = requirements.RiskStore
type GuidanceStore = requirements.GuidanceStore
type TargetStore = requirements.TargetStore
type PolicyDimensionStore = requirements.PolicyDimensionStore

type EvidenceStore = evidence.EvidenceStore
type CertificationStore = evidence.CertificationStore

type AuditLogStore = audit.AuditLogStore
type DraftAuditLogStore = audit.DraftAuditLogStore
type EvidenceAssessmentStore = audit.EvidenceAssessmentStore

type RequirementStore = posture.RequirementStore
type InventoryStore = posture.InventoryStore

type TrustSignalStore = certify.TrustSignalStore

// ── Re-exported sentinel errors ─────────────────────────────────────────────

var ErrRequirementNotFound = audit.ErrRequirementNotFound
var ErrDraftAlreadyPromoted = audit.ErrDraftAlreadyPromoted
var ErrDraftNotFound = audit.ErrDraftNotFound

// ── Re-exported variables ───────────────────────────────────────────────────

var ValidClassifications = audit.ValidClassifications

// ── Infrastructure interfaces ───────────────────────────────────────────────

// TesseraAppender defines operations for appending entries to a transparency log.
type TesseraAppender interface {
	Add(ctx context.Context, entry []byte) (uint64, error)
}

// EventPublisher emits NATS events for evidence, policies, and targets.
// Implemented by *bus.Bus; nil-safe (callers check before use).
type EventPublisher interface {
	PublishEvidence(policyID string, count int)
	PublishDraftAuditLog(draftID, policyID, summary string)
	PublishPolicyNew(logIndex uint64, policyID string)
	PublishTargetRegistered(logIndex uint64, targetID, registeredBy string)
}

// HealthChecker verifies backend connectivity for health probes.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// JWTVerifier validates JWT tokens and extracts claims.
type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*auth.JWTClaims, error)
}

// ── Stores composition ──────────────────────────────────────────────────────

// Stores groups all domain store interfaces for handler registration.
type Stores struct {
	Policies            PolicyStore
	Mappings            MappingStore
	Evidence            EvidenceStore
	Blob                blob.BlobStore
	AuditLogs           AuditLogStore
	DraftAuditLogs      DraftAuditLogStore
	Requirements        RequirementStore
	Controls            ControlStore
	Guidance            GuidanceStore
	Threats             ThreatStore
	Risks               RiskStore
	Catalogs            CatalogStore
	EvidenceAssessments EvidenceAssessmentStore
	Certifications      CertificationStore
	EventPublisher      EventPublisher
	HealthChecker       HealthChecker
	Inventory           InventoryStore
	Users               auth.UserStore
	Registry            *RegistryConfig
	IngestTracker       *IngestTracker
	IngestPublisher     IngestPublisher
	TesseraAppender     TesseraAppender
	JWTVerifier         JWTVerifier
	Targets             TargetStore
	PolicyDimensions    PolicyDimensionStore
}

// InsertBundleArtifact inserts a bundle artifact if the Evidence store supports it.
func (s Stores) InsertBundleArtifact(ctx context.Context, b BundleArtifactRow) error {
	type bundleInserter interface {
		InsertBundleArtifact(ctx context.Context, b BundleArtifactRow) error
	}
	if bi, ok := s.Evidence.(bundleInserter); ok {
		return bi.InsertBundleArtifact(ctx, b)
	}
	return nil
}

// ── Store struct ────────────────────────────────────────────────────────────

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
	_ TrustSignalStore        = (*Store)(nil)
	_ InventoryStore          = (*Store)(nil)
)

// New wraps a PostgreSQL connection pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}
