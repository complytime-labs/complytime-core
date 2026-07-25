package events

import (
	"context"
	"encoding/json"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	natsgo "github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"

	"github.com/complytime-labs/complytime-core/events"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// EventPublisher publishes CloudEvents to NATS for evidence lifecycle notifications.
type EventPublisher struct {
	nc     *natsgo.Conn
	source string
}

// NewEventPublisher creates a CloudEvents publisher backed by NATS.
func NewEventPublisher(nc *natsgo.Conn, source string) *EventPublisher {
	return &EventPublisher{nc: nc, source: source}
}

// PublishEvidenceIngested publishes a CloudEvent when evidence is ingested (before sealing).
func (p *EventPublisher) PublishEvidenceIngested(ctx context.Context, data events.EvidenceIngestedData) error {
	initTelemetry()

	ctx, span := eventsTracer.Start(ctx, "events.publish")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", events.TypeEvidenceIngested),
		attribute.String("subject.id", data.SubjectID),
	)

	event := cloudevents.NewEvent()
	event.SetType(events.TypeEvidenceIngested)
	event.SetSource(p.source)
	event.SetSubject(data.SubjectID)

	// Inject trace context for downstream continuation
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if tp := carrier.Get("traceparent"); tp != "" {
		event.SetExtension("traceparent", tp)
	}
	if ts := carrier.Get("tracestate"); ts != "" {
		event.SetExtension("tracestate", ts)
	}

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
func (p *EventPublisher) PublishEvidenceSealed(ctx context.Context, data events.EvidenceSealedData) error {
	initTelemetry()

	ctx, span := eventsTracer.Start(ctx, "events.publish")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", events.TypeEvidenceSealed),
		attribute.String("subject.id", data.SubjectID),
	)

	event := cloudevents.NewEvent()
	event.SetType(events.TypeEvidenceSealed)
	event.SetSource(p.source)
	event.SetSubject(data.SubjectID)

	// Inject trace context for downstream continuation
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if tp := carrier.Get("traceparent"); tp != "" {
		event.SetExtension("traceparent", tp)
	}
	if ts := carrier.Get("tracestate"); ts != "" {
		event.SetExtension("tracestate", ts)
	}

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
	initTelemetry()

	ctx, span := eventsTracer.Start(ctx, "events.publish")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", events.TypeSubjectRegistered),
		attribute.String("subject.id", subjectID),
	)

	event := cloudevents.NewEvent()
	event.SetType(events.TypeSubjectRegistered)
	event.SetSource(p.source)
	event.SetSubject(subjectID)

	// Inject trace context for downstream continuation
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if tp := carrier.Get("traceparent"); tp != "" {
		event.SetExtension("traceparent", tp)
	}
	if ts := carrier.Get("tracestate"); ts != "" {
		event.SetExtension("tracestate", ts)
	}

	data := events.SubjectRegisteredData{
		SubjectID: subjectID,
	}

	if err := event.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return fmt.Errorf("setting event data: %w", err)
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	if err := p.nc.Publish(natsinfra.SubjectRegistration, eventJSON); err != nil {
		return fmt.Errorf("publishing subject registered event: %w", err)
	}

	return nil
}
