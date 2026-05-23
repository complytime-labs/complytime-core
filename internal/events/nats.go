// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	SubjectEvidence  = "core.evidence"
	SubjectDraft     = "core.draft"
	SubjectIngestRaw = "core.ingest"
)

// SubjectPrefix is the NATS subject namespace for studio events.
// Kept for backward compatibility with evidence subscribers.
const SubjectPrefix = SubjectEvidence

// EvidenceEvent is published after evidence is ingested for a policy.
type EvidenceEvent struct {
	PolicyID    string    `json:"policy_id"`
	RecordCount int       `json:"record_count"`
	Timestamp   time.Time `json:"timestamp"`
}

// DraftAuditLogEvent is published after a draft audit log is created.
type DraftAuditLogEvent struct {
	DraftID   string    `json:"draft_id"`
	PolicyID  string    `json:"policy_id"`
	Summary   string    `json:"summary"`
	Timestamp time.Time `json:"timestamp"`
}

// Bus wraps a NATS connection for studio event publishing and subscribing.
type Bus struct {
	conn *nats.Conn
}

// Connect creates a new Bus connected to the given NATS URL.
// Returns (nil, nil) if natsURL is empty (NATS disabled).
func Connect(natsURL string) (*Bus, error) {
	if natsURL == "" {
		return nil, nil
	}
	nc, err := nats.Connect(natsURL,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			slog.Warn("nats disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			slog.Info("nats reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	slog.Info("nats connected", "url", natsURL)
	return &Bus{conn: nc}, nil
}

// PublishEvidence publishes an evidence event. Errors are logged, never returned
// — callers must not block ingestion on NATS availability.
func (b *Bus) PublishEvidence(policyID string, recordCount int) {
	if b == nil || b.conn == nil {
		return
	}
	evt := EvidenceEvent{
		PolicyID:    policyID,
		RecordCount: recordCount,
		Timestamp:   time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	subject := SubjectPrefix + "." + policyID
	if err := b.conn.Publish(subject, data); err != nil {
		slog.Warn("nats publish failed", "subject", subject, "error", err)
	}
}

// PublishDraftAuditLog publishes a draft audit log event. Errors are logged,
// never returned — callers must not block on NATS availability.
func (b *Bus) PublishDraftAuditLog(draftID, policyID, summary string) {
	if b == nil || b.conn == nil {
		return
	}
	evt := DraftAuditLogEvent{
		DraftID:   draftID,
		PolicyID:  policyID,
		Summary:   summary,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	subject := SubjectDraft + "." + policyID
	if err := b.conn.Publish(subject, data); err != nil {
		slog.Warn("nats publish failed", "subject", subject, "error", err)
	}
}

// PublisherIdentity contains JWT-verified publisher information.
type PublisherIdentity struct {
	Sub      string `json:"sub"`      // JWT sub claim
	Issuer   string `json:"issuer"`   // JWT iss claim
	Type     string `json:"type"`     // "pipeline" or "service"
	Verified bool   `json:"verified"` // Always true after JWT verification
}

// IngestRawEvent carries a raw Gemara artifact for async processing.
type IngestRawEvent struct {
	JobID             string            `json:"job_id"`
	LogIndex          uint64            `json:"log_index"`          // Tessera transparency log position
	YAML              []byte            `json:"yaml"`
	PublisherIdentity PublisherIdentity `json:"publisher_identity"`
	Timestamp         time.Time         `json:"timestamp"`
}

// PublishIngestRaw publishes a raw artifact for async ingest. Returns an
// error so the HTTP handler can fail the job immediately on NATS issues.
func (b *Bus) PublishIngestRaw(jobID string, yaml []byte) error {
	if b == nil || b.conn == nil {
		return fmt.Errorf("nats not connected")
	}
	evt := IngestRawEvent{
		JobID:     jobID,
		YAML:      yaml,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal ingest event: %w", err)
	}
	if err := b.conn.Publish(SubjectIngestRaw, data); err != nil {
		return fmt.Errorf("nats publish %s: %w", SubjectIngestRaw, err)
	}
	return nil
}

// SubscribeIngestRaw subscribes to raw ingest events for async processing.
func (b *Bus) SubscribeIngestRaw(handler func(IngestRawEvent)) (*nats.Subscription, error) {
	if b == nil || b.conn == nil {
		return nil, nil
	}
	return b.conn.Subscribe(SubjectIngestRaw, func(msg *nats.Msg) {
		var evt IngestRawEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Warn("nats unmarshal failed", "error", err)
			return
		}
		handler(evt)
	})
}

// SubscribeEvidence subscribes to all evidence events (core.evidence.>).
// The gateway uses this for the in-process certifier pipeline.
func (b *Bus) SubscribeEvidence(handler func(EvidenceEvent)) (*nats.Subscription, error) {
	if b == nil || b.conn == nil {
		return nil, nil
	}
	return b.conn.Subscribe(SubjectPrefix+".>", func(msg *nats.Msg) {
		var evt EvidenceEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Warn("nats unmarshal failed", "error", err)
			return
		}
		handler(evt)
	})
}

// Close drains and closes the NATS connection.
func (b *Bus) Close() {
	if b == nil || b.conn == nil {
		return
	}
	_ = b.conn.Drain()
}
