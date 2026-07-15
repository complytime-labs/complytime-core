package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	natsgo "github.com/nats-io/nats.go"

	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

const (
	// EventTypeEvidenceIngested is emitted when evidence is ingested (before sealing).
	EventTypeEvidenceIngested = "dev.complytime.evidence.ingested"

	// EventTypeEvidenceSealed is emitted when evidence is sealed into the locker.
	EventTypeEvidenceSealed = "dev.complytime.evidence.sealed"

	// EventTypeSubjectRegistered is emitted when a subject is registered or updated.
	EventTypeSubjectRegistered = "dev.complytime.subject.registered"

	// EventSource is the CloudEvents source identifier for the gateway.
	EventSource = "complytime-gateway"
)

// EventPublisher publishes CloudEvents to NATS for evidence lifecycle notifications.
type EventPublisher struct {
	nc *natsgo.Conn
}

// NewEventPublisher creates a CloudEvents publisher backed by NATS.
func NewEventPublisher(nc *natsgo.Conn) *EventPublisher {
	return &EventPublisher{nc: nc}
}

// PublisherIdentity identifies the entity that produced evidence.
type PublisherIdentity struct {
	Issuer string `json:"issuer"`
	Sub    string `json:"sub"`
}

// EvidenceIngestedData is the CloudEvents data payload for evidence.ingested events.
// Emitted by both S3+Lambda and gateway when evidence arrives but before it's sealed.
type EvidenceIngestedData struct {
	ContentDigest string            `json:"contentDigest"`
	ArtifactType  string            `json:"artifactType"`
	StorageRef    string            `json:"storageRef"`
	SubjectID     string            `json:"subjectId"`
	Publisher     PublisherIdentity `json:"publisher"`
	ShardID       *string           `json:"shardId,omitempty"`
}

// EvidenceSealedData is the CloudEvents data payload for evidence.sealed events.
// Emitted by gateway only, after the locker confirms evidence is sealed with a receipt.
type EvidenceSealedData struct {
	ContentDigest string  `json:"contentDigest"`
	LogIndex      int64   `json:"logIndex"`
	ReceiptDigest string  `json:"receiptDigest"`
	ReceiptType   string  `json:"receiptType"`
	StorageRef    string  `json:"storageRef"`
	SubjectID     string  `json:"subjectId"`
	ShardID       *string `json:"shardId,omitempty"`
}

// SubjectRegisteredData is the CloudEvents data payload for subject.registered events.
type SubjectRegisteredData struct {
	SubjectID string `json:"subjectId"`
}

// PublishEvidenceIngested publishes a CloudEvent when evidence is ingested (before sealing).
func (p *EventPublisher) PublishEvidenceIngested(ctx context.Context, data EvidenceIngestedData) error {
	event := cloudevents.NewEvent()
	event.SetType(EventTypeEvidenceIngested)
	event.SetSource(EventSource)
	event.SetSubject(data.SubjectID)

	if err := event.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return fmt.Errorf("setting event data: %w", err)
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	subject := natsinfra.EvidenceIngestedSubject(data.SubjectID)
	if err := p.nc.Publish(subject, eventJSON); err != nil {
		return fmt.Errorf("publishing ingested event: %w", err)
	}
	return nil
}

// PublishEvidenceSealed publishes a CloudEvent when evidence is sealed into the locker.
func (p *EventPublisher) PublishEvidenceSealed(ctx context.Context, data EvidenceSealedData) error {
	event := cloudevents.NewEvent()
	event.SetType(EventTypeEvidenceSealed)
	event.SetSource(EventSource)
	event.SetSubject(data.SubjectID)

	if err := event.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return fmt.Errorf("setting event data: %w", err)
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	subject := natsinfra.EvidenceSealedSubject(data.SubjectID)
	if err := p.nc.Publish(subject, eventJSON); err != nil {
		return fmt.Errorf("publishing sealed event: %w", err)
	}
	return nil
}

// PublishSubjectRegistered publishes a CloudEvent when a subject is registered.
func (p *EventPublisher) PublishSubjectRegistered(ctx context.Context, subjectID string) error {
	event := cloudevents.NewEvent()
	event.SetType(EventTypeSubjectRegistered)
	event.SetSource(EventSource)
	event.SetSubject(subjectID)

	data := SubjectRegisteredData{
		SubjectID: subjectID,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return fmt.Errorf("failed to set CloudEvent data: %w", err)
	}

	// Serialize CloudEvent to JSON and publish to NATS
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal CloudEvent: %w", err)
	}

	if err := p.nc.Publish(natsinfra.SubjectRegistration, eventJSON); err != nil {
		return fmt.Errorf("failed to publish CloudEvent to NATS: %w", err)
	}

	return nil
}
