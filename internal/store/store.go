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
	Policies            requirements.PolicyStore
	Mappings            requirements.MappingStore
	Evidence            evidence.EvidenceStore
	Blob                blob.BlobStore
	AuditLogs           audit.AuditLogStore
	DraftAuditLogs      audit.DraftAuditLogStore
	Requirements        posture.RequirementStore
	Controls            requirements.ControlStore
	Guidance            requirements.GuidanceStore
	Threats             requirements.ThreatStore
	Risks               requirements.RiskStore
	Catalogs            requirements.CatalogStore
	EvidenceAssessments audit.EvidenceAssessmentStore
	Certifications      evidence.CertificationStore
	EventPublisher      EventPublisher
	HealthChecker       HealthChecker
	Inventory           posture.InventoryStore
	Users               auth.UserStore
	Registry            *RegistryConfig
	IngestTracker       *IngestTracker
	IngestPublisher     IngestPublisher
	TesseraAppender     TesseraAppender
	JWTVerifier         JWTVerifier
	Targets             requirements.TargetStore
	PolicyDimensions    requirements.PolicyDimensionStore
}

// InsertBundleArtifact inserts a bundle artifact if the Evidence store supports it.
func (s Stores) InsertBundleArtifact(ctx context.Context, b requirements.BundleArtifactRow) error {
	type bundleInserter interface {
		InsertBundleArtifact(ctx context.Context, b requirements.BundleArtifactRow) error
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
	_ requirements.PolicyStore          = (*Store)(nil)
	_ requirements.MappingStore         = (*Store)(nil)
	_ evidence.EvidenceStore            = (*Store)(nil)
	_ audit.AuditLogStore               = (*Store)(nil)
	_ requirements.ControlStore         = (*Store)(nil)
	_ requirements.ThreatStore          = (*Store)(nil)
	_ requirements.RiskStore            = (*Store)(nil)
	_ requirements.CatalogStore         = (*Store)(nil)
	_ audit.EvidenceAssessmentStore     = (*Store)(nil)
	_ audit.DraftAuditLogStore          = (*Store)(nil)
	_ posture.RequirementStore          = (*Store)(nil)
	_ evidence.CertificationStore       = (*Store)(nil)
	_ requirements.GuidanceStore        = (*Store)(nil)
	_ requirements.TargetStore          = (*Store)(nil)
	_ requirements.PolicyDimensionStore = (*Store)(nil)
	_ certify.TrustSignalStore          = (*Store)(nil)
	_ posture.InventoryStore            = (*Store)(nil)
)

// New wraps a PostgreSQL connection pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}
