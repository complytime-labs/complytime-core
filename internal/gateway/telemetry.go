package gateway

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	gwTracer metric.Meter
	gwOnce   sync.Once

	// Ingest metrics
	ingestTotal    metric.Int64Counter
	ingestDuration metric.Float64Histogram
)

// initTelemetry initializes the gateway's telemetry instruments.
// Called once via sync.Once from handler methods that use metrics.
func initTelemetry() {
	gwOnce.Do(func() {
		gwTracer = otel.Meter("complytime-gateway")

		var err error

		// Ingest metrics
		ingestTotal, err = gwTracer.Int64Counter("gateway.ingest.total",
			metric.WithDescription("Total ingest requests by status and artifact type"),
		)
		if err != nil {
			panic("failed to create gateway.ingest.total: " + err.Error())
		}

		ingestDuration, err = gwTracer.Float64Histogram("gateway.ingest.duration",
			metric.WithDescription("Ingest request duration by artifact type"),
			metric.WithUnit("s"),
		)
		if err != nil {
			panic("failed to create gateway.ingest.duration: " + err.Error())
		}
	})
}
