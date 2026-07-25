package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/locker"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	ctotel "github.com/complytime-labs/complytime-core/internal/otel"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

var version = "dev"

func main() {
	// Get configuration from environment
	dataPath := os.Getenv("LOCKER_DATA_PATH")
	if dataPath == "" {
		dataPath = "/data/ledgers"
	}

	listenAddr := os.Getenv("LOCKER_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8081"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	jwtIssuers := os.Getenv("JWT_ISSUERS")
	if jwtIssuers == "" {
		fmt.Fprintln(os.Stderr, "JWT_ISSUERS is required")
		os.Exit(1)
	}

	jwtAudience := os.Getenv("JWT_AUDIENCE")
	if jwtAudience == "" {
		fmt.Fprintln(os.Stderr, "JWT_AUDIENCE is required")
		os.Exit(1)
	}

	ctx := context.Background()

	// Initialize OTel (sets up slog bridge)
	otelShutdown, err := ctotel.Init(ctx, ctotel.Config{
		ServiceName:    "complytime-locker",
		ServiceVersion: version,
	})
	if err != nil {
		slog.Error("failed to initialize otel", "error", err)
		os.Exit(1)
	}

	// Create locker
	lk, err := locker.NewLocker(dataPath)
	if err != nil {
		slog.Error("failed to create locker", "error", err)
		os.Exit(1)
	}

	// Open existing ledgers on startup
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = lk.OpenExistingLedgers(openCtx)
	cancel()
	if err != nil {
		slog.Error("failed to open existing ledgers", "error", err)
		os.Exit(1)
	}

	// Register gauge callbacks for locker metrics
	if err := lk.RegisterGauges(ctx); err != nil {
		slog.Error("failed to register locker gauges", "error", err)
		os.Exit(1)
	}

	// Connect to NATS
	slog.Info("connecting to nats", "url", natsURL)
	nc, err := natsinfra.Connect(natsURL)
	if err != nil {
		slog.Error("failed to connect to nats", "error", err)
		os.Exit(1)
	}

	// Get JetStream context
	js, err := jetstream.New(nc)
	if err != nil {
		slog.Error("failed to get jetstream context", "error", err)
		os.Exit(1)
	}

	// Ensure NATS infrastructure
	slog.Info("ensuring nats infrastructure")
	if err := natsinfra.EnsureInfrastructure(ctx, js); err != nil {
		slog.Error("failed to ensure nats infrastructure", "error", err)
		os.Exit(1)
	}

	// Create trust store
	trustStore, err := trust.NewTrustStore(js)
	if err != nil {
		slog.Error("failed to create trust store", "error", err)
		os.Exit(1)
	}

	// Create event publisher
	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-locker")

	issuerList := strings.Split(jwtIssuers, ",")
	auth, err := authn.NewJWTAuthenticator(ctx, issuerList, jwtAudience)
	if err != nil {
		slog.Error("failed to create jwt authenticator", "error", err)
		os.Exit(1)
	}

	policySet, err := authz.LoadEmbeddedPolicies()
	if err != nil {
		slog.Error("failed to load cedar policies", "error", err)
		os.Exit(1)
	}

	// Create worker
	worker := locker.NewWorker(js, lk, eventPublisher)

	// Start worker in background
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	workerErrCh := make(chan error, 1)
	go func() {
		if err := worker.Start(workerCtx); err != nil {
			workerErrCh <- err
		}
	}()

	// Create HTTP handler and server
	handler := locker.NewHandler(lk, auth, policySet, trustStore, eventPublisher)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("starting locker server", "addr", listenAddr, "dataPath", dataPath)

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		slog.Info("locker listening", "addr", listenAddr, "data", dataPath)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigChan:
		slog.Info("shutdown signal received, gracefully shutting down")
	case err := <-errCh:
		slog.Error("server error", "error", err)
		os.Exit(1)
	case err := <-workerErrCh:
		slog.Error("worker error", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop worker first
	workerCancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}

	// Flush OTel providers
	otelShutdown(shutdownCtx)

	// Drain NATS
	if err := nc.Drain(); err != nil {
		slog.Error("nats drain error", "error", err)
		os.Exit(1)
	}

	// Close locker
	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := lk.Close(closeCtx); err != nil {
		slog.Error("locker close error", "error", err)
		os.Exit(1)
	}

	slog.Info("locker server stopped successfully")
}
