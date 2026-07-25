package authz

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	authzMeter metric.Meter
	authzOnce  sync.Once

	// Cedar authorization metrics
	cedarDecisionTotal metric.Int64Counter
	cedarDuration      metric.Float64Histogram
)

// initTelemetry initializes the authz telemetry instruments.
// Called once via sync.Once from the middleware.
func initTelemetry() {
	authzOnce.Do(func() {
		// Use a neutral meter name since authz is shared across services
		authzMeter = otel.Meter("complytime-authz")

		var err error

		cedarDecisionTotal, err = authzMeter.Int64Counter("cedar.decision.total",
			metric.WithDescription("Total Cedar authorization decisions by decision and action"),
		)
		if err != nil {
			panic("failed to create cedar.decision.total: " + err.Error())
		}

		cedarDuration, err = authzMeter.Float64Histogram("cedar.duration",
			metric.WithDescription("Cedar authorization duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			panic("failed to create cedar.duration: " + err.Error())
		}
	})
}
