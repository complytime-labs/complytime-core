package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	appconfig "github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/graph"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	flags := flag.NewFlagSet("graph", flag.ExitOnError)
	configPath := flags.String("config", "", "path to YAML config file")
	flags.Parse(os.Args[1:]) //nolint:errcheck // ExitOnError never returns an error

	k, err := appconfig.Load(*configPath, flags)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	cfg, err := graph.LoadGraphConfig(k)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	driver, err := neo4j.NewDriverWithContext(cfg.MemgraphURL, neo4j.NoAuth())
	if err != nil {
		slog.Error("failed to connect to memgraph", "error", err)
		os.Exit(1)
	}
	defer driver.Close(ctx)

	writer := graph.NewWriter(driver)

	nc, err := natsinfra.Connect(cfg.NatsURL)
	if err != nil {
		slog.Error("failed to connect to nats", "error", err)
		os.Exit(1)
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		slog.Error("failed to get jetstream context", "error", err)
		os.Exit(1)
	}

	if err := natsinfra.EnsureInfrastructure(ctx, js); err != nil {
		slog.Error("failed to ensure nats infrastructure", "error", err)
		os.Exit(1)
	}

	tokenSource := authn.NewFileTokenSource(cfg.TokenFile)
	lockerClient := &http.Client{
		Transport: authn.NewTokenTransport(tokenSource, http.DefaultTransport),
		Timeout:   30 * time.Second,
	}

	loader := graph.NewLoader(js, writer, cfg.LockerURL, lockerClient)
	if err := loader.Start(ctx); err != nil {
		slog.Error("failed to start loader", "error", err)
		os.Exit(1)
	}

	primary, publishers, err := appconfig.BuildIssuers(ctx, cfg.Issuers)
	if err != nil {
		slog.Error("failed to build issuers", "error", err)
		os.Exit(1)
	}

	// Graph service has no trust store — no JWK store or JTI store.
	auth := authn.NewIssuerRegistry(primary, publishers, nil, nil, cfg.JWTAudience)

	policySet, err := authz.LoadEmbeddedPolicies(cfg.CedarPolicyDir)
	if err != nil {
		slog.Error("failed to load cedar policies", "error", err)
		os.Exit(1)
	}

	handler := graph.NewHandler(writer, auth, policySet)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		slog.Info("graph service starting", "addr", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down graph service")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown failed", "error", err)
	}
	if err := loader.Stop(); err != nil {
		slog.Error("loader stop failed", "error", err)
	}
}
