package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/complytime-labs/complytime-core/internal/graph"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

func main() {
	// Required env vars
	natsURL := requireEnv("NATS_URL")
	lockerURL := requireEnv("LOCKER_URL")
	lockerSecret := requireEnv("LOCKER_SECRET")
	memgraphURL := requireEnv("MEMGRAPH_URL")
	jwtIssuers := requireEnv("JWT_ISSUERS")
	jwtAudience := requireEnv("JWT_AUDIENCE")

	listenAddr := os.Getenv("GRAPH_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8082"
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Connect to Memgraph
	driver, err := neo4j.NewDriverWithContext(memgraphURL, neo4j.NoAuth())
	if err != nil {
		slog.Error("failed to connect to memgraph", "error", err)
		os.Exit(1)
	}
	defer driver.Close(ctx)

	writer := graph.NewWriter(driver)

	// Connect to NATS
	nc, err := natsinfra.Connect(natsURL)
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

	// Create locker HTTP client with auth
	tokenSource := authn.NewStaticTokenSource(lockerSecret)
	lockerClient := &http.Client{
		Transport: authn.NewTokenTransport(tokenSource, http.DefaultTransport),
		Timeout:   30 * time.Second,
	}

	// Start loader
	loader := graph.NewLoader(js, writer, lockerURL, lockerClient)
	if err := loader.Start(ctx); err != nil {
		slog.Error("failed to start loader", "error", err)
		os.Exit(1)
	}

	// Set up HTTP server
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

	handler := graph.NewHandler(writer, auth, policySet)
	server := &http.Server{Addr: listenAddr, Handler: handler}

	go func() {
		slog.Info("graph service starting", "addr", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down graph service")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	loader.Stop()
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", key)
		os.Exit(1)
	}
	return v
}
