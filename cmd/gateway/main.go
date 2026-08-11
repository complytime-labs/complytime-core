package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
	"github.com/complytime-labs/complytime-core/internal/authz"
	appconfig "github.com/complytime-labs/complytime-core/internal/config"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	flags := flag.NewFlagSet("gateway", flag.ExitOnError)
	configPath := flags.String("config", "", "path to YAML config file")
	flags.Parse(os.Args[1:]) //nolint:errcheck // ExitOnError never returns an error

	k, err := appconfig.Load(*configPath, flags)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	cfg, err := gateway.LoadGatewayConfig(k)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	slog.Info("connecting to nats", "url", cfg.NatsURL)
	nc, err := natsinfra.Connect(cfg.NatsURL)
	if err != nil {
		slog.Error("failed to connect to nats", "error", err)
		os.Exit(1)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		slog.Error("failed to get jetstream context", "error", err)
		os.Exit(1)
	}

	slog.Info("ensuring nats infrastructure")
	if err := natsinfra.EnsureInfrastructure(ctx, js); err != nil {
		slog.Error("failed to ensure nats infrastructure", "error", err)
		os.Exit(1)
	}

	trustStore, err := trust.NewTrustStore(js)
	if err != nil {
		slog.Error("failed to create trust store", "error", err)
		os.Exit(1)
	}

	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-gateway")

	policySet, err := authz.LoadEmbeddedPolicies(cfg.CedarPolicyDir)
	if err != nil {
		slog.Error("failed to load cedar policies", "error", err)
		os.Exit(1)
	}

	primary, publishers, err := appconfig.BuildIssuers(ctx, cfg.Issuers)
	if err != nil {
		slog.Error("failed to build issuers", "error", err)
		os.Exit(1)
	}

	jwkLookup := publisher.JWKLookupFunc(func(ctx context.Context, issuerID string) (*publisher.StoredJWK, error) {
		rec, err := trustStore.GetJWK(ctx, issuerID)
		if err != nil || rec == nil {
			return nil, err
		}
		return &publisher.StoredJWK{JWK: rec.JWK, NotAfter: rec.NotAfter}, nil
	})

	registry, err := authn.NewIssuerRegistry(primary, publishers, jwkLookup, trustStore, cfg.JWTAudience)
	if err != nil {
		slog.Error("failed to build issuer registry", "error", err)
		os.Exit(1)
	}

	schemas, err := gateway.NewSchemaRegistry()
	if err != nil {
		slog.Error("failed to load gemara schemas", "error", err)
		os.Exit(1)
	}

	gwHandler := gateway.NewHandler(trustStore, js, nc, eventPublisher, schemas).WithRegistry(registry)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Get("/healthz", gwHandler.HealthCheck)

	authzCfg := authz.MiddlewareConfig{
		AdminGroup:   cfg.Issuers.OIDC.AdminGroup,
		AuditorGroup: cfg.Issuers.OIDC.AuditorGroup,
	}

	r.Group(func(r chi.Router) {
		r.Use(authn.AuthMiddleware(registry))
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted, authzCfg))
		r.Post("/admin/subjects", gwHandler.RegisterSubject)
		r.Put("/admin/subjects/{subjectId}/trust", func(w http.ResponseWriter, req *http.Request) {
			subjectID := chi.URLParam(req, "subjectId")
			gwHandler.ModifyTrust(w, req, subjectID)
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(authn.AuthMiddleware(registry))
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted, authzCfg))
		r.Post("/api/ingest", gwHandler.IngestArtifact)
	})

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	slog.Info("starting gateway server", "addr", cfg.ListenAddr)

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigChan:
		slog.Info("shutdown signal received, gracefully shutting down")
	case err := <-serverErrCh:
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}
	if err := nc.Drain(); err != nil {
		slog.Error("nats drain error", "error", err)
		os.Exit(1)
	}

	slog.Info("gateway server stopped successfully")
}
