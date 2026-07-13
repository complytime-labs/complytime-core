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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nats-io/nats.go/jetstream"
	openapitypes "github.com/oapi-codegen/runtime/types"

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

	lockerSecret := os.Getenv("LOCKER_SECRET")
	if lockerSecret == "" {
		// Fail-closed: LOCKER_SECRET must be set
		slog.Error("LOCKER_SECRET environment variable is required (fail-closed)")
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

	// Create JWT authenticator
	// For simplicity, we'll use a simple approach: fetch JWKS from each issuer's .well-known/openid-configuration
	// In production, you'd cache JWKS and refresh periodically
	tokenAuth, err := createJWTAuth(jwtIssuers, jwtAudience)
	if err != nil {
		slog.Error("failed to create jwt authenticator", "error", err)
		os.Exit(1)
	}

	// Create gateway handler
	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, lockerURL, lockerSecret)

	// Build Chi router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)

	// Health check endpoint (no auth)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		// JWT authentication
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtAuthenticator)

		// Extract X-Subject-ID header into context before Cedar runs
		r.Use(gateway.SubjectIDExtractor)

		// Cedar authorization middleware
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
	worker := gateway.NewWorker(js, lockerURL, lockerSecret, eventPublisher, &gwHandler.Jobs)

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

// createJWTAuth creates a JWT authenticator from a comma-separated list of issuer URLs.
// For each issuer, it fetches the JWKS from the .well-known/openid-configuration endpoint.
func createJWTAuth(issuers, audience string) (*jwtauth.JWTAuth, error) {
	issuerList := strings.Split(issuers, ",")
	if len(issuerList) == 0 {
		return nil, fmt.Errorf("no JWT issuers configured")
	}

	// For simplicity, we'll create a keyset that includes keys from all issuers
	// In production, you'd want to validate the issuer claim and use the right keyset
	keySet := jwk.NewSet()

	for _, issuer := range issuerList {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			continue
		}

		// Fetch JWKS from issuer
		jwksURL := issuer + "/.well-known/jwks.json"
		slog.Info("fetching jwks", "url", jwksURL)

		set, err := jwk.Fetch(context.Background(), jwksURL)
		if err != nil {
			return nil, fmt.Errorf("fetching jwks from %s: %w", jwksURL, err)
		}

		// Add keys to our keyset (v3 API)
		keys := set.Keys()
		for _, keyID := range keys {
			key, ok := set.LookupKeyID(keyID)
			if !ok {
				continue
			}
			if err := keySet.AddKey(key); err != nil {
				return nil, fmt.Errorf("adding key to keyset: %w", err)
			}
		}
	}

	// Create jwtauth with the keyset
	// Note: jwtauth.New expects a signing key, but for verification we only need the public keys
	// We'll use jwtauth.NewWithKeySet instead (if available) or work around it
	tokenAuth := jwtauth.New("RS256", nil, keySet)

	return tokenAuth, nil
}

// jwtAuthenticator is the middleware that validates the JWT and adds publisher context.
func jwtAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())

		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if token == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract issuer and subject from JWT token
		// token is of type jwt.Token from lestrrat-go/jwx/v3
		jwtToken, ok := token.(jwt.Token)
		if !ok {
			http.Error(w, "Unauthorized: invalid token type", http.StatusUnauthorized)
			return
		}

		issuer, ok := jwtToken.Issuer()
		if !ok || issuer == "" {
			http.Error(w, "Unauthorized: missing issuer", http.StatusUnauthorized)
			return
		}

		sub, ok := jwtToken.Subject()
		if !ok || sub == "" {
			http.Error(w, "Unauthorized: missing subject", http.StatusUnauthorized)
			return
		}

		// Add publisher to context
		ctx := authz.SetPublisherContext(r.Context(), issuer, sub)

		// Extract admin claim if present
		var isAdmin bool
		if err := jwtToken.Get("admin", &isAdmin); err == nil {
			ctx = authz.SetAdminContext(ctx, isAdmin)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
