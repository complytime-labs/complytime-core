package otel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	promclient "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds OTel initialization parameters.
type Config struct {
	ServiceName    string
	ServiceVersion string
}

// Init initializes OTel providers (traces, metrics, logs) and starts the
// Prometheus /metrics HTTP server. Returns a shutdown function that flushes
// all providers. Safe to call shutdown multiple times.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating otel resource: %w", err)
	}

	var shutdownFuncs []func(context.Context) error

	// Cleanup on error: if we return early with an error, call accumulated shutdowns
	defer func() {
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, fn := range shutdownFuncs {
				_ = fn(cleanupCtx)
			}
		}
	}()

	// TracerProvider
	var tp *sdktrace.TracerProvider
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint != "" {
		exporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("creating otlp trace exporter: %w", err)
		}
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
		)
		shutdownFuncs = append(shutdownFuncs, tp.Shutdown)
	} else {
		tp = sdktrace.NewTracerProvider(sdktrace.WithResource(res))
		shutdownFuncs = append(shutdownFuncs, tp.Shutdown)
	}
	otel.SetTracerProvider(tp)

	// Propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// MeterProvider (Prometheus)
	promExporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(promExporter),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	shutdownFuncs = append(shutdownFuncs, mp.Shutdown)

	// Start Prometheus HTTP server
	port := os.Getenv("OTEL_PROMETHEUS_PORT")
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promclient.Handler())
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("listening on prometheus port %s: %w", port, err)
	}
	metricsSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := metricsSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("prometheus metrics server error", "error", err)
		}
	}()
	slog.Info("prometheus metrics server started", "addr", listener.Addr().String())
	shutdownFuncs = append(shutdownFuncs, metricsSrv.Shutdown)

	// LoggerProvider (otelslog bridge)
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res))
	otelHandler := otelslog.NewHandler(cfg.ServiceName, otelslog.WithLoggerProvider(lp))
	stdoutHandler := slog.NewJSONHandler(os.Stdout, nil)
	multiHandler := newMultiHandler(otelHandler, stdoutHandler)
	slog.SetDefault(slog.New(multiHandler))
	shutdownFuncs = append(shutdownFuncs, lp.Shutdown)

	var once sync.Once
	shutdown := func(ctx context.Context) error {
		var shutdownErr error
		once.Do(func() {
			for _, fn := range shutdownFuncs {
				if err := fn(ctx); err != nil {
					slog.Error("otel shutdown error", "error", err)
					if shutdownErr == nil {
						shutdownErr = err
					}
				}
			}
		})
		return shutdownErr
	}

	return shutdown, nil
}

// multiHandler is a slog.Handler that fans out to multiple handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(handlers ...slog.Handler) *multiHandler {
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var firstErr error
	for _, handler := range h.handlers {
		if err := handler.Handle(ctx, record); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}
