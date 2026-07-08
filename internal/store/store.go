// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// ── Infrastructure interfaces ───────────────────────────────────────────────

// TesseraAppender defines operations for appending entries to a transparency log.
type TesseraAppender interface {
	Add(ctx context.Context, entry []byte) (uint64, error)
}

// EventPublisher emits NATS events for evidence, policies, and targets.
type EventPublisher interface {
	PublishEvidence(policyID, targetID, artifactType string, count int, logIndex uint64)
	PublishDraftAuditLog(draftID, policyID, targetID, summary string)
	PublishPolicyNew(logIndex uint64, policyID, targetID string)
	PublishTargetRegistered(logIndex uint64, targetID, registeredBy string)
}

// JWTVerifier validates JWT tokens and extracts claims.
type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*auth.JWTClaims, error)
}

// ── Stores composition ──────────────────────────────────────────────────────

// Stores groups the dependencies needed by ingest and import handlers.
type Stores struct {
	Targets           requirements.TargetStore
	TrustedPublishers requirements.TrustedPublisherStore
	EventPublisher    EventPublisher
	Registry          *RegistryConfig
	IngestTracker     *IngestTracker
	IngestPublisher   IngestPublisher
	TesseraAppender   TesseraAppender
	JWTVerifier       JWTVerifier
	Authorizer        auth.Authorizer
	IngestRateLimit   httputil.RateLimitOptions
}
