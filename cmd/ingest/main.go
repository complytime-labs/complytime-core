// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/version"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventbus "github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	version.CheckFlags(version.Info{
		Name:        "complytime-ingest",
		Description: "compliance artifact ingestion and transparency log service",
		EnvHelp: `
Environment variables:
  NATS_URL                       NATS broker URL (required)
  PORT                           HTTP listen port (default: 8080)
  LISTEN_HOST                    HTTP listen address (default: 0.0.0.0)
  INTERNAL_PORT                  Internal tlog listener port (default: 8081)
  INTERNAL_LISTEN_HOST           Internal listener address (default: 127.0.0.1)

  TESSERA_PATH                   Transparency log storage path (default: /data/tessera)
  TESSERA_SIGNER_KEY_PATH        Ed25519 signing key for log entries
  TESSERA_CHECKPOINT_INTERVAL    Checkpoint creation interval (default: 10m)
  TESSERA_WITNESS_POLICY_PATH    Witness policy config file path
  TESSERA_WITNESS_TIMEOUT        Witness API call timeout (default: 5s)
  TESSERA_WITNESS_FAIL_OPEN      Allow ops if witness unavailable (default: false)

  JWT_ISSUERS                    Comma-separated OIDC issuer URLs
  JWT_AUDIENCE                   JWT audience claim (default: complytime)
  CEDAR_POLICY_DIR               Directory containing .cedar policy files
  CEDAR_POLL_INTERVAL            Policy reload interval (default: 30s)

  INGEST_RATE_LIMIT              Requests per second (default: 10)
  INGEST_RATE_BURST              Burst capacity (default: 20)
  NATS_INGEST_MAX_DELIVER        Max delivery attempts per message (default: 5)
  NATS_INGEST_ACK_WAIT           Ack wait before redelivery (default: 30s)

  CORS_ORIGINS                   Comma-separated allowed CORS origins
  REGISTRY_INSECURE              Allow HTTP OCI registries (default: false)
  KNOWN_REGISTRIES               Comma-separated allowed OCI registries
  KNOWN_ENGINES                  Comma-separated allowed container engines

  BLOB_ENDPOINT                  S3-compatible endpoint (optional)
  BLOB_BUCKET                    S3 bucket name
  BLOB_ACCESS_KEY                S3 access key
  BLOB_SECRET_KEY                S3 secret key
  BLOB_USE_SSL                   Use TLS for blob storage (default: false)
`,
	})

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.GatewayFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	bus, busErr := eventbus.Connect(cfg.NatsURL, cfg.CloudEventsSource)
	if busErr != nil {
		slog.Error("nats connection failed", "error", busErr)
		os.Exit(1)
	}
	defer bus.Close()
	slog.Info("nats connected", "url", cfg.NatsURL, "jetstream", true)

	ingestStreamCfg := eventbus.IngestStreamConfig{
		MaxDeliver: cfg.IngestMaxDeliver,
		AckWait:    cfg.IngestAckWait,
	}
	if err := bus.EnsureIngestStream(ctx, ingestStreamCfg); err != nil {
		slog.Error("jetstream stream setup failed", "error", err)
		os.Exit(1)
	}

	// Initialize NATS KV stores for publisher trust and targets
	publisherTrust, err := eventbus.NewPublisherTrustKV(ctx, bus.JetStream())
	if err != nil {
		slog.Error("publisher trust KV init failed", "error", err)
		os.Exit(1)
	}
	targetStore, err := eventbus.NewTargetStoreKV(ctx, bus.JetStream())
	if err != nil {
		slog.Error("target store KV init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("nats KV stores ready", "buckets", []string{"publisher-trust", "targets-registry"})

	var pub store.EventPublisher = bus
	ingestTracker := store.NewIngestTracker()

	// Initialize Tessera client for transparency log
	tesseraOpts := tessera.DefaultOptions()
	tesseraOpts.CheckpointTime = cfg.TesseraCheckpointInterval
	tesseraOpts.SignerKeyPath = cfg.TesseraSignerKeyPath
	tesseraOpts.WitnessPolicyPath = cfg.TesseraWitnessPolicyPath
	tesseraOpts.WitnessTimeout = cfg.TesseraWitnessTimeout
	tesseraOpts.WitnessFailOpen = cfg.TesseraWitnessFailOpen
	tesseraClient, err := tessera.NewClient(ctx, cfg.TesseraPath, tesseraOpts)
	if err != nil {
		slog.Error("tessera client init failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := tesseraClient.Close(); err != nil {
			slog.Warn("tessera client close failed", "error", err)
		}
	}()
	slog.Info("tessera client ready", "path", cfg.TesseraPath)

	// Initialize JWT verifier
	if len(cfg.JWTIssuers) == 0 {
		slog.Warn("JWT_ISSUERS not configured — trusted publisher ingestion will be unavailable")
	}
	jwtVerifier := auth.NewJWTVerifier(ctx, cfg.JWTIssuers, cfg.JWTAudience)
	slog.Info("jwt verifier ready", "allowed_issuers", len(cfg.JWTIssuers), "audience", cfg.JWTAudience)

	// Initialize Cedar authorizer
	authorizer, err := authz.NewAuthorizer(cfg.CedarPolicyDir)
	if err != nil {
		slog.Error("cedar authorizer init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("cedar authorizer ready", "policy_dir", cfg.CedarPolicyDir)

	registryConfig := store.LoadRegistryConfig()

	stores := store.Stores{
		Targets:           targetStore,
		TrustedPublishers: publisherTrust,
		EventPublisher:    pub,
		Registry:          registryConfig,
		IngestTracker:     ingestTracker,
		IngestPublisher:   bus,
		TesseraAppender:   tesseraClient,
		JWTVerifier:       jwtVerifier,
		Authorizer:        authorizer,
		IngestRateLimit: httputil.RateLimitOptions{
			Rate:  cfg.IngestRateLimit,
			Burst: cfg.IngestRateBurst,
		},
	}

	ingestHandler := store.IngestWorker(ctx, stores, pub, ingestTracker, tesseraClient)
	ingestCC, ingestCCErr := bus.ConsumeIngest(ctx, ingestHandler)
	if ingestCCErr != nil {
		slog.Error("jetstream ingest consumer failed", "error", ingestCCErr)
		os.Exit(1)
	}
	defer ingestCC.Stop()
	slog.Info("jetstream ingest consumer started", "consumer", "ingest-worker")

	// Start policy watcher if configured
	if cfg.CedarPolicyDir != "" && cfg.CedarPollInterval > 0 {
		watcher := authz.NewWatcher(authorizer, cfg.CedarPolicyDir, cfg.CedarPollInterval)
		watcher.Start()
		defer watcher.Stop()
		slog.Info("cedar policy watcher started", "interval", cfg.CedarPollInterval)
	}

	authHandler := auth.NewHandler(authorizer)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true, LogURI: true, LogMethod: true, LogLatency: true, LogError: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			slog.Info("request",
				"method", v.Method, "uri", v.URI,
				"status", v.Status, "latency_ms", v.Latency.Milliseconds(),
				"error", v.Error,
			)
			return nil
		},
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		ContentSecurityPolicy: httputil.ContentSecurityPolicy,
		XFrameOptions:         "DENY",
		ContentTypeNosniff:    "nosniff",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	if len(cfg.CORSOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins:     cfg.CORSOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
			MaxAge:           consts.CORSMaxAgeSecs,
		}))
		slog.Info("CORS enabled", "origins", cfg.CORSOrigins)
	}

	// Internal listener for tlog reads (witnesses, internal tooling).
	// No auth — access controlled at the network layer.
	internal := echo.New()
	internal.HideBanner = true
	internal.HidePort = true
	internal.Use(middleware.Recover())

	tessera.RegisterTilesAPI(internal, cfg.TesseraPath)
	tessera.RegisterWitnessedStatus(internal, cfg.TesseraPath)
	internal.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	tessera.RegisterTilesAPI(e, cfg.TesseraPath)
	tessera.RegisterWitnessedStatus(e, cfg.TesseraPath)

	authHandler.Register(e)
	e.Use(authHandler.Middleware())

	e.GET("/healthz", func(c echo.Context) error {
		if bus.Conn().Status().String() != "CONNECTED" {
			return c.String(http.StatusServiceUnavailable, "nats unreachable")
		}
		return c.String(http.StatusOK, "ok")
	})

	apiGroup := e.Group("/api")
	apiGroup.Use(middleware.BodyLimit(fmt.Sprintf("%dM", consts.MaxRequestBody>>20)))
	store.Register(apiGroup, stores)
	config.Register(apiGroup, config.Options{
		Values: map[string]string{
			"github_org":        cfg.GitHubOrg,
			"github_repo":       cfg.GitHubRepo,
			"registry_insecure": strconv.FormatBool(cfg.RegistryInsecure),
		},
	})

	apiGroup.GET("/system-info", func(c echo.Context) error {
		natsStatus := "connected"
		if bus.Conn().Status().String() != "CONNECTED" {
			natsStatus = "unreachable"
		}
		return c.JSON(http.StatusOK, map[string]any{
			"version": cfg.Version,
			"storage": "Tessera (POSIX) + NATS KV",
			"nats":    natsStatus,
		})
	})

	slog.Info("api routes registered", "groups", []string{"ingest", "import", "config"})

	// Start internal listener
	internalAddr := net.JoinHostPort(cfg.InternalListenHost, cfg.InternalPort)
	go func() {
		slog.Info("internal tlog listener starting", "addr", internalAddr)
		if err := internal.Start(internalAddr); err != nil && err != http.ErrServerClosed {
			slog.Error("internal listener failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(shutdownCtx)
		_ = internal.Shutdown(shutdownCtx)
	}()

	addr := net.JoinHostPort(cfg.ListenHost, cfg.Port)

	e.Server.ReadTimeout = consts.ServerReadTimeout
	e.Server.WriteTimeout = consts.ServerWriteTimeout
	e.Server.IdleTimeout = consts.ServerIdleTimeout
	e.Server.MaxHeaderBytes = 1 << 20

	slog.Info("ingest service starting", "addr", addr)
	if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
		slog.Error("http server failed", "error", err)
		os.Exit(1)
	}
}
