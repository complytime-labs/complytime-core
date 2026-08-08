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

	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
	"github.com/complytime-labs/complytime-core/internal/authz"
	appconfig "github.com/complytime-labs/complytime-core/internal/config"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/locker"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	flags := flag.NewFlagSet("locker", flag.ExitOnError)
	configPath := flags.String("config", "", "path to YAML config file")
	flags.Parse(os.Args[1:]) //nolint:errcheck // ExitOnError never returns an error

	k, err := appconfig.Load(*configPath, flags)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	cfg, err := locker.LoadLockerConfig(k)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	lk, err := locker.NewLocker(cfg.DataPath)
	if err != nil {
		slog.Error("failed to create locker", "error", err)
		os.Exit(1)
	}

	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = lk.OpenExistingLedgers(openCtx)
	cancel()
	if err != nil {
		slog.Error("failed to open existing ledgers", "error", err)
		os.Exit(1)
	}

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

	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-locker")

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

	auth := authn.NewIssuerRegistry(primary, publishers, jwkLookup, trustStore, cfg.JWTAudience)

	policySet, err := authz.LoadEmbeddedPolicies(cfg.CedarPolicyDir)
	if err != nil {
		slog.Error("failed to load cedar policies", "error", err)
		os.Exit(1)
	}

	worker := locker.NewWorker(js, lk, eventPublisher)

	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	workerErrCh := make(chan error, 1)
	go func() {
		if err := worker.Start(workerCtx); err != nil {
			workerErrCh <- err
		}
	}()

	adminSub := locker.NewAdminSubscriber(nc, lk, eventPublisher)
	adminErrCh := make(chan error, 1)
	go func() {
		if err := adminSub.Start(workerCtx); err != nil {
			adminErrCh <- err
		}
	}()

	authzCfg := authz.MiddlewareConfig{
		AdminGroup:   cfg.Issuers.OIDC.AdminGroup,
		AuditorGroup: cfg.Issuers.OIDC.AuditorGroup,
	}
	handler := locker.NewHandler(lk, auth, policySet, trustStore, eventPublisher, authzCfg)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("starting locker server", "addr", cfg.ListenAddr, "dataPath", cfg.DataPath)

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

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
	case err := <-adminErrCh:
		slog.Error("admin subscriber error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	workerCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}
	if err := nc.Drain(); err != nil {
		slog.Error("nats drain error", "error", err)
		os.Exit(1)
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := lk.Close(closeCtx); err != nil {
		slog.Error("locker close error", "error", err)
		os.Exit(1)
	}

	slog.Info("locker server stopped successfully")
}
