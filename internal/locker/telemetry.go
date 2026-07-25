package locker

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	lockerMeter  metric.Meter
	lockerTracer trace.Tracer
	lockerOnce   sync.Once

	// Seal metrics
	sealTotal    metric.Int64Counter
	sealDuration metric.Float64Histogram

	// Fetch metrics
	fetchTotal    metric.Int64Counter
	fetchDuration metric.Float64Histogram

	// Verify metrics
	verifyTotal metric.Int64Counter
)

// initTelemetry initializes the locker's telemetry instruments.
// Called once via sync.Once from handler methods that use metrics.
func initTelemetry() {
	lockerOnce.Do(func() {
		lockerMeter = otel.Meter("complytime-locker")
		lockerTracer = otel.Tracer("complytime-locker")

		var err error

		// Seal metrics
		sealTotal, err = lockerMeter.Int64Counter("locker.seal.total",
			metric.WithDescription("Total seal operations by subject ID"),
		)
		if err != nil {
			panic("failed to create locker.seal.total: " + err.Error())
		}

		sealDuration, err = lockerMeter.Float64Histogram("locker.seal.duration",
			metric.WithDescription("Seal operation duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			panic("failed to create locker.seal.duration: " + err.Error())
		}

		// Fetch metrics
		fetchTotal, err = lockerMeter.Int64Counter("locker.fetch.total",
			metric.WithDescription("Total fetch operations by subject ID"),
		)
		if err != nil {
			panic("failed to create locker.fetch.total: " + err.Error())
		}

		fetchDuration, err = lockerMeter.Float64Histogram("locker.fetch.duration",
			metric.WithDescription("Fetch operation duration"),
			metric.WithUnit("s"),
		)
		if err != nil {
			panic("failed to create locker.fetch.duration: " + err.Error())
		}

		// Verify metrics
		verifyTotal, err = lockerMeter.Int64Counter("locker.verify.total",
			metric.WithDescription("Total verify operations by found status"),
		)
		if err != nil {
			panic("failed to create locker.verify.total: " + err.Error())
		}
	})
}
