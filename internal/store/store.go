// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/cedar-policy/cedar-go"
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

// CedarAuthorizer provides Cedar-based authorization.
type CedarAuthorizer interface {
	IsAuthorized(principal cedar.EntityUID, principalAttrs map[string]cedar.Value, action cedar.EntityUID, resource cedar.EntityUID, resourceAttrs map[string]cedar.Value) (bool, error)
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
	Authorizer        CedarAuthorizer
	IngestRateLimit   httputil.RateLimitOptions
}
