// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	SubjectEvidence         = "core.evidence"
	SubjectDraft            = "core.draft"
	SubjectIngestRaw        = "core.ingest"
	SubjectPolicyNew        = "core.policy.new"
	SubjectTargetRegistered = "core.target.registered"

	StreamIngest         = "INGEST"
	ConsumerIngestWorker = "ingest-worker"
	DefaultMaxDeliver    = 5
	DefaultAckWait       = 30 * time.Second
	DefaultDedupeWindow  = 2 * time.Minute
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

// IngestStreamConfig holds tunable parameters for the JetStream ingest stream.
type IngestStreamConfig struct {
	MaxDeliver int
	AckWait    time.Duration
}

// Bus wraps a NATS connection for studio event publishing and subscribing.
type Bus struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

// JetStream returns the underlying JetStream client for KV operations.
func (b *Bus) JetStream() jetstream.JetStream {
	return b.js
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

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	slog.Info("nats connected", "url", natsURL, "jetstream", true)
	return &Bus{conn: nc, js: js}, nil
}

// EnsureIngestStream creates or updates the INGEST stream for durable ingest
// processing. Idempotent — safe to call on every startup.
func (b *Bus) EnsureIngestStream(ctx context.Context, cfg IngestStreamConfig) error {
	if b == nil || b.js == nil {
		return fmt.Errorf("jetstream not initialized")
	}

	maxDeliver := cfg.MaxDeliver
	if maxDeliver <= 0 {
		maxDeliver = DefaultMaxDeliver
	}
	ackWait := cfg.AckWait
	if ackWait <= 0 {
		ackWait = DefaultAckWait
	}

	_, err := b.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       StreamIngest,
		Subjects:   []string{SubjectIngestRaw},
		Retention:  jetstream.WorkQueuePolicy,
		MaxMsgs:    -1,
		MaxBytes:   -1,
		Duplicates: DefaultDedupeWindow,
	})
	if err != nil {
		return fmt.Errorf("create/update stream %s: %w", StreamIngest, err)
	}

	_, err = b.js.CreateOrUpdateConsumer(ctx, StreamIngest, jetstream.ConsumerConfig{
		Durable:       ConsumerIngestWorker,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		MaxDeliver:    maxDeliver,
		FilterSubject: SubjectIngestRaw,
	})
	if err != nil {
		return fmt.Errorf("create/update consumer %s: %w", ConsumerIngestWorker, err)
	}

	slog.Info("jetstream ingest stream ready",
		"stream", StreamIngest,
		"consumer", ConsumerIngestWorker,
		"max_deliver", maxDeliver,
		"ack_wait", ackWait,
	)
	return nil
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

// IngestRef is the slim JetStream message envelope for async ingest.
// YAML is not included — worker fetches from Tessera by log_index.
type IngestRef struct {
	JobID             string            `json:"job_id"`
	LogIndex          uint64            `json:"log_index"`
	PublisherIdentity PublisherIdentity `json:"publisher_identity"`
	BundleID          string            `json:"bundle_id,omitempty"`
	OCIReference      string            `json:"oci_reference,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
}

// PolicyEvent is published when a new Policy artifact is ingested.
type PolicyEvent struct {
	LogIndex  uint64    `json:"log_index"`
	PolicyID  string    `json:"policy_id"`
	Timestamp time.Time `json:"timestamp"`
}

// TargetRegisteredEvent is published when a TargetRegistration is ingested.
type TargetRegisteredEvent struct {
	LogIndex     uint64    `json:"log_index"`
	TargetID     string    `json:"target_id"`
	RegisteredBy string    `json:"registered_by"`
	Timestamp    time.Time `json:"timestamp"`
}

// PublishIngest publishes an IngestRef to the JetStream INGEST stream.
// Uses job_id as Nats-Msg-Id for deduplication.
func (b *Bus) PublishIngest(ctx context.Context, ref IngestRef) error {
	if b == nil || b.js == nil {
		return fmt.Errorf("jetstream not initialized")
	}
	data, err := json.Marshal(ref)
	if err != nil {
		return fmt.Errorf("marshal ingest ref: %w", err)
	}
	_, err = b.js.Publish(ctx, SubjectIngestRaw, data, jetstream.WithMsgID(ref.JobID))
	if err != nil {
		return fmt.Errorf("jetstream publish %s: %w", SubjectIngestRaw, err)
	}
	return nil
}

// IngestMsgHandler processes a single JetStream ingest message.
// Implementations must call msg.Ack(), msg.NakWithDelay(), or msg.Term().
type IngestMsgHandler func(ctx context.Context, ref IngestRef, msg jetstream.Msg)

// ConsumeIngest starts a durable pull consumer on the INGEST stream.
// Returns a ConsumeContext that must be stopped on shutdown.
func (b *Bus) ConsumeIngest(ctx context.Context, handler IngestMsgHandler) (jetstream.ConsumeContext, error) {
	if b == nil || b.js == nil {
		return nil, fmt.Errorf("jetstream not initialized")
	}

	consumer, err := b.js.Consumer(ctx, StreamIngest, ConsumerIngestWorker)
	if err != nil {
		return nil, fmt.Errorf("get consumer %s: %w", ConsumerIngestWorker, err)
	}

	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		var ref IngestRef
		if err := json.Unmarshal(msg.Data(), &ref); err != nil {
			slog.Warn("jetstream ingest unmarshal failed", "error", err)
			_ = msg.Term()
			return
		}
		handler(ctx, ref, msg)
	})
	if err != nil {
		return nil, fmt.Errorf("consume %s: %w", ConsumerIngestWorker, err)
	}

	slog.Info("jetstream ingest consumer started", "consumer", ConsumerIngestWorker)
	return cc, nil
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

// PublishPolicyNew broadcasts that a new Policy artifact was ingested.
func (b *Bus) PublishPolicyNew(logIndex uint64, policyID string) {
	if b == nil || b.conn == nil {
		return
	}
	evt := PolicyEvent{
		LogIndex:  logIndex,
		PolicyID:  policyID,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	if err := b.conn.Publish(SubjectPolicyNew, data); err != nil {
		slog.Warn("nats publish failed", "subject", SubjectPolicyNew, "error", err)
	}
}

// PublishTargetRegistered broadcasts that a new target was registered.
func (b *Bus) PublishTargetRegistered(logIndex uint64, targetID, registeredBy string) {
	if b == nil || b.conn == nil {
		return
	}
	evt := TargetRegisteredEvent{
		LogIndex:     logIndex,
		TargetID:     targetID,
		RegisteredBy: registeredBy,
		Timestamp:    time.Now().UTC(),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("nats marshal failed", "error", err)
		return
	}
	if err := b.conn.Publish(SubjectTargetRegistered, data); err != nil {
		slog.Warn("nats publish failed", "subject", SubjectTargetRegistered, "error", err)
	}
}

// SubscribePolicyNew subscribes to new policy events.
func (b *Bus) SubscribePolicyNew(handler func(PolicyEvent)) (*nats.Subscription, error) {
	if b == nil || b.conn == nil {
		return nil, nil
	}
	return b.conn.Subscribe(SubjectPolicyNew, func(msg *nats.Msg) {
		var evt PolicyEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Warn("nats unmarshal failed", "error", err)
			return
		}
		handler(evt)
	})
}

// SubscribeTargetRegistered subscribes to target registration events.
func (b *Bus) SubscribeTargetRegistered(handler func(TargetRegisteredEvent)) (*nats.Subscription, error) {
	if b == nil || b.conn == nil {
		return nil, nil
	}
	return b.conn.Subscribe(SubjectTargetRegistered, func(msg *nats.Msg) {
		var evt TargetRegisteredEvent
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
