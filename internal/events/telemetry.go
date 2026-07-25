package events

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

var (
	eventsTracer trace.Tracer
	eventsOnce   sync.Once
)

// initTelemetry initializes the events telemetry tracer.
// Called once via sync.Once from the publisher methods.
func initTelemetry() {
	eventsOnce.Do(func() {
		eventsTracer = otel.Tracer("complytime-events")
	})
}
