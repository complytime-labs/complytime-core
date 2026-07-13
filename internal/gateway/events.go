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

// EvidenceSealedData is the CloudEvents data payload for evidence.sealed events.
type EvidenceSealedData struct {
	SubjectID     string `json:"subjectId"`
	LogIndex      int64  `json:"logIndex"`
	Digest        string `json:"digest"`
	ContentFormat string `json:"contentFormat"`
	RefDigest     string `json:"refDigest,omitempty"`
}

// SubjectRegisteredData is the CloudEvents data payload for subject.registered events.
type SubjectRegisteredData struct {
	SubjectID string `json:"subjectId"`
}

// PublishEvidenceSealed publishes a CloudEvent when evidence is sealed.
func (p *EventPublisher) PublishEvidenceSealed(ctx context.Context, subjectID string, logIndex int64, digest, contentFormat string) error {
	return p.PublishEvidenceSealedWithRef(ctx, subjectID, logIndex, digest, contentFormat, "")
}

// PublishEvidenceSealedWithRef publishes a CloudEvent when evidence is sealed, including a reference digest
// for channel attestation back-references (e.g., the DSSE envelope digest that wraps the actual evidence).
func (p *EventPublisher) PublishEvidenceSealedWithRef(ctx context.Context, subjectID string, logIndex int64, digest, contentFormat, refDigest string) error {
	event := cloudevents.NewEvent()
	event.SetType(EventTypeEvidenceSealed)
	event.SetSource(EventSource)
	event.SetSubject(subjectID)

	data := EvidenceSealedData{
		SubjectID:     subjectID,
		LogIndex:      logIndex,
		Digest:        digest,
		ContentFormat: contentFormat,
		RefDigest:     refDigest,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return fmt.Errorf("failed to set CloudEvent data: %w", err)
	}

	// Serialize CloudEvent to JSON and publish to NATS
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal CloudEvent: %w", err)
	}

	subject := natsinfra.EvidenceSubject(subjectID)
	if err := p.nc.Publish(subject, eventJSON); err != nil {
		return fmt.Errorf("failed to publish CloudEvent to NATS: %w", err)
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
