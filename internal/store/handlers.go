// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/blob"
	"github.com/complytime-labs/complytime-core/internal/identity"
)

func jsonError(c echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
}

// EventPublisher emits NATS events for evidence and draft audit logs.
// Implemented by *events.Bus; nil-safe (callers check before use).
type EventPublisher interface {
	PublishEvidence(policyID string, count int)
	PublishDraftAuditLog(draftID, policyID, summary string)
}

// HealthChecker verifies backend connectivity for health probes.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// JWTVerifier validates JWT tokens and extracts claims.
type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*auth.JWTClaims, error)
}

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
	Users               identity.UserStore
	Registry            *RegistryConfig
	IngestTracker       *IngestTracker
	IngestPublisher     IngestRawPublisher
	TesseraAppender     TesseraAppender
	JWTVerifier         JWTVerifier
}

// Register mounts all public store API endpoints on g (typically e.Group("/api")).
// Internal (agent-only) endpoints are registered via RegisterInternal.
func Register(g *echo.Group, s Stores) {
	registerPolicyRoutes(g, s)
	registerIngestRoutes(g, s)
	registerEvidenceRoutes(g, s)
	registerInventoryRoutes(g, s)
	registerCertificationsRoutes(g, s)
	registerAuditRoutes(g, s)
	registerCatalogRoutes(g, s)
	registerPostureAndRequirementRoutes(g, s)
	registerDraftAuditRoutes(g, s)
	registerThreatAndRiskRoutes(g, s)
}
