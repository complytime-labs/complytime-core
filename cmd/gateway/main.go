package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nats-io/nats.go/jetstream"
	openapitypes "github.com/oapi-codegen/runtime/types"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/complytime-labs/complytime-core/internal/gateway"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Read configuration from environment
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	lockerURL := os.Getenv("LOCKER_URL")
	if lockerURL == "" {
		lockerURL = "http://localhost:8081"
	}

	tokenFile := os.Getenv("TOKEN_FILE")
	if tokenFile == "" {
		// Fail-closed: TOKEN_FILE must be set
		slog.Error("TOKEN_FILE environment variable is required (fail-closed)")
		os.Exit(1)
	}

	jwtIssuers := os.Getenv("JWT_ISSUERS")
	if jwtIssuers == "" {
		slog.Error("JWT_ISSUERS environment variable is required")
		os.Exit(1)
	}

	jwtAudience := os.Getenv("JWT_AUDIENCE")
	if jwtAudience == "" {
		// Fail-closed: JWT_AUDIENCE must be set
		slog.Error("JWT_AUDIENCE environment variable is required (fail-closed)")
		os.Exit(1)
	}

	listenAddr := os.Getenv("GATEWAY_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	ctx := context.Background()

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

	// Ensure infrastructure
	slog.Info("ensuring nats infrastructure")
	if err := natsinfra.EnsureInfrastructure(ctx, js); err != nil {
		slog.Error("failed to ensure nats infrastructure", "error", err)
		os.Exit(1)
	}

	// Create trust store
	trustStore, err := gateway.NewTrustStore(js)
	if err != nil {
		slog.Error("failed to create trust store", "error", err)
		os.Exit(1)
	}

	// Create event publisher
	eventPublisher := gateway.NewEventPublisher(nc)

	// Load Cedar policies
	policySet, err := authz.LoadEmbeddedPolicies()
	if err != nil {
		slog.Error("failed to load cedar policies", "error", err)
		os.Exit(1)
	}

	// Create JWT authenticator with auto-refreshing JWKS
	issuerList := strings.Split(jwtIssuers, ",")
	jwtAuth, err := authn.NewJWTAuthenticator(ctx, issuerList, jwtAudience)
	if err != nil {
		slog.Error("failed to create jwt authenticator", "error", err)
		os.Exit(1)
	}

	// Build locker HTTP client with token auth
	lockerTokenSource := authn.NewFileTokenSource(tokenFile)
	lockerClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: authn.NewTokenTransport(lockerTokenSource, http.DefaultTransport),
	}

	// Create gateway handler
	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, lockerURL, lockerClient)

	// Build Chi router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)

	// Health check endpoint (no auth)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authn.AuthMiddleware(jwtAuth))
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted))

		// API routes
		r.Post("/api/ingest", gwHandler.IngestArtifact)
		r.Post("/api/admin/subjects", gwHandler.RegisterSubject)
		r.Get("/api/ingest/jobs/{jobId}", func(w http.ResponseWriter, r *http.Request) {
			jobIDStr := chi.URLParam(r, "jobId")
			var jobID openapitypes.UUID
			if err := jobID.UnmarshalText([]byte(jobIDStr)); err != nil {
				http.Error(w, "Invalid job ID", http.StatusBadRequest)
				return
			}
			gwHandler.GetJobStatus(w, r, jobID)
		})
	})

	// Create worker (needs access to the same jobs map as the handler)
	worker := gateway.NewWorker(js, lockerURL, lockerClient, eventPublisher, &gwHandler.Jobs)

	// Start worker in background
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	workerErrCh := make(chan error, 1)
	go func() {
		if err := worker.Start(workerCtx); err != nil {
			workerErrCh <- err
		}
	}()

	// Create HTTP server
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	slog.Info("starting gateway server", "addr", listenAddr)

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	// Wait for shutdown signal or error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigChan:
		slog.Info("shutdown signal received, gracefully shutting down")
	case err := <-serverErrCh:
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

	// Drain NATS
	if err := nc.Drain(); err != nil {
		slog.Error("nats drain error", "error", err)
		os.Exit(1)
	}

	slog.Info("gateway server stopped successfully")
}
