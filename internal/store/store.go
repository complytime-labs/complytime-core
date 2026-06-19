// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

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

// JWTVerifier validates JWT tokens and extracts claims.
type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*auth.JWTClaims, error)
}

// ── Stores composition ──────────────────────────────────────────────────────

// Stores groups domain store interfaces needed by ingest and import handlers.
// Postgres-backed query stores have been removed (Phase 2); these fields are
// retained because the async ingest worker and OCI import still write through
// them until Phase 4 migrates persistence to Tessera-only.
type Stores struct {
	Policies          requirements.PolicyStore
	Mappings          requirements.MappingStore
	Evidence          evidence.EvidenceStore
	Controls          requirements.ControlStore
	Guidance          requirements.GuidanceStore
	Threats           requirements.ThreatStore
	Risks             requirements.RiskStore
	Catalogs          requirements.CatalogStore
	Targets           requirements.TargetStore
	TrustedPublishers requirements.TrustedPublisherStore
	EventPublisher    EventPublisher
	Registry          *RegistryConfig
	IngestTracker     *IngestTracker
	IngestPublisher   IngestPublisher
	TesseraAppender   TesseraAppender
	JWTVerifier       JWTVerifier
	IngestRateLimit   httputil.RateLimitOptions
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
