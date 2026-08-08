package trust

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	trustMeter metric.Meter
	trustOnce  sync.Once

	// Trust lookup metrics
	trustLookupDuration metric.Float64Histogram
	trustRejectionTotal metric.Int64Counter
)

// initTelemetry initializes the trust telemetry instruments.
// Called once via sync.Once from IsPublisherTrusted.
func initTelemetry() {
	trustOnce.Do(func() {
		// Use a neutral meter name since trust is shared across services
		trustMeter = otel.Meter("complytime-trust")

		var err error

		trustLookupDuration, err = trustMeter.Float64Histogram("trust.lookup.duration",
			metric.WithDescription("Trust lookup duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			slog.Error("failed to create trust.lookup.duration", "error", err)
		}

		trustRejectionTotal, err = trustMeter.Int64Counter("trust.rejection.total",
			metric.WithDescription("Total trust rejections by subject ID"),
		)
		if err != nil {
			slog.Error("failed to create trust.rejection.total", "error", err)
		}
	})
}
