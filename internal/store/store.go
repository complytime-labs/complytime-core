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
	IngestRateLimit   httputil.RateLimitOptions
}
