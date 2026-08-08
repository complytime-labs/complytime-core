package gateway

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	gwMeter metric.Meter
	gwOnce  sync.Once

	// Ingest metrics
	ingestTotal    metric.Int64Counter
	ingestDuration metric.Float64Histogram
)

// initTelemetry initializes the gateway's telemetry instruments.
// Called once via sync.Once from handler methods that use metrics.
func initTelemetry() {
	gwOnce.Do(func() {
		gwMeter = otel.Meter("complytime-gateway")

		var err error

		// Ingest metrics
		ingestTotal, err = gwMeter.Int64Counter("gateway.ingest.total",
			metric.WithDescription("Total ingest requests by status and artifact type"),
		)
		if err != nil {
			slog.Error("failed to create gateway.ingest.total", "error", err)
		}

		ingestDuration, err = gwMeter.Float64Histogram("gateway.ingest.duration",
			metric.WithDescription("Ingest request duration by artifact type"),
			metric.WithUnit("s"),
		)
		if err != nil {
			slog.Error("failed to create gateway.ingest.duration", "error", err)
		}
	})
}
