// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	nethttputil "net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/blob"
	eventbus "github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/certify"
	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/consts"
	pgstore "github.com/complytime-labs/complytime-core/internal/db"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.GatewayFromEnv()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	pgClient, err := pgstore.New(ctx, pgstore.Config{URL: cfg.PostgresURL})
	if err != nil {
		slog.Error("postgres connection failed", "error", err)
		os.Exit(1)
	}
	defer pgClient.Close()
	if err = pgClient.EnsureSchema(ctx); err != nil {
		slog.Error("postgres schema init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("postgres ready")
	st := store.New(pgClient.Pool())

	var blobStore blob.BlobStore
	if cfg.BlobEnabled() {
		if cfg.BlobAccessKey == "" || cfg.BlobSecretKey == "" {
			slog.Error("blob storage enabled but BLOB_ACCESS_KEY / BLOB_SECRET_KEY missing")
			os.Exit(1)
		}
		blobCfg := blob.Config{
			Endpoint:  cfg.BlobEndpoint,
			Bucket:    cfg.BlobBucket,
			AccessKey: cfg.BlobAccessKey,
			SecretKey: cfg.BlobSecretKey,
			UseSSL:    cfg.BlobUseSSL,
		}
		bs, err := blob.NewMinioBlobStore(ctx, blobCfg)
		if err != nil {
			slog.Error("blob storage init failed", "error", err)
			os.Exit(1)
		}
		blobStore = bs
		slog.Info("blob storage configured", "endpoint", cfg.BlobEndpoint, "bucket", cfg.BlobBucket)
	}

	registryConfig := store.LoadRegistryConfig()

	go func() {
		if err := store.PopulateMappingEntries(ctx, st); err != nil {
			slog.Warn("mapping entries backfill failed", "error", err)
		}
		if err := store.PopulateControls(ctx, st, st); err != nil {
			slog.Warn("controls backfill failed", "error", err)
		}
		if err := store.PopulateThreats(ctx, st, st); err != nil {
			slog.Warn("threats backfill failed", "error", err)
		}
		if err := store.PopulateRisks(ctx, st, st); err != nil {
			slog.Warn("risks backfill failed", "error", err)
		}
		if err := store.PopulateEffectiveControls(ctx, st, st, st); err != nil {
			slog.Warn("effective controls backfill failed", "error", err)
		}
		if err := store.PopulatePolicyCriteria(ctx, st, st); err != nil {
			slog.Warn("policy criteria backfill failed", "error", err)
		}
		slog.Info("startup backfill complete")
	}()

	bus, busErr := eventbus.Connect(cfg.NatsURL)
	if busErr != nil {
		slog.Error("nats connection failed", "error", busErr)
		os.Exit(1)
	}
	defer bus.Close()

	ingestStreamCfg := eventbus.IngestStreamConfig{
		MaxDeliver: cfg.IngestMaxDeliver,
		AckWait:    cfg.IngestAckWait,
	}
	if err := bus.EnsureIngestStream(ctx, ingestStreamCfg); err != nil {
		slog.Error("jetstream stream setup failed", "error", err)
		os.Exit(1)
	}

	var pub store.EventPublisher = bus
	ingestTracker := store.NewIngestTracker()

	// Initialize Tessera client for transparency log
	tesseraOpts := tessera.DefaultOptions()
	tesseraOpts.SignerKeyPath = cfg.TesseraSignerKeyPath
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

	// Initialize JWT verifier with allowed issuers from environment
	if len(cfg.JWTIssuers) == 0 {
		slog.Warn("JWT_ISSUERS not configured — trusted publisher ingestion will be unavailable")
	}
	jwtVerifier := auth.NewJWTVerifier(ctx, cfg.JWTIssuers, cfg.JWTAudience)
	slog.Info("jwt verifier ready", "allowed_issuers", len(cfg.JWTIssuers), "audience", cfg.JWTAudience)

	stores := store.Stores{
		Policies:            st,
		Mappings:            st,
		Evidence:            st,
		Blob:                blobStore,
		AuditLogs:           st,
		DraftAuditLogs:      st,
		Requirements:        st,
		Controls:            st,
		Guidance:            st,
		Threats:             st,
		Risks:               st,
		Catalogs:            st,
		EvidenceAssessments: st,
		Certifications:      st,
		EventPublisher:      pub,
		HealthChecker:       pgClient,
		Inventory:           st,
		Users:               pgClient,
		Registry:            registryConfig,
		IngestTracker:       ingestTracker,
		IngestPublisher:     bus,
		TesseraAppender:     tesseraClient,
		JWTVerifier:         jwtVerifier,
		Targets:             st,
		PolicyDimensions:    st,
		TrustSignals:        st,
		Coverage:            st,
	}
	slog.Info("store API registered", "routes", []string{
		"/api/policies",
		"/api/ingest",
		"/api/ingest/jobs/:job_id",
		"/api/audit-logs",
		"/api/mappings",
	})

	pipeline := buildCertifierPipeline(cfg.KnownRegistries, cfg.KnownEngines)
	certAdapter := &certificationAdapter{store: st}
	certHandler := certify.CertificationHandler(ctx, pipeline, certAdapter, certAdapter)
	certDebouncer := certify.NewDebouncer(consts.EventDebounceDuration, certHandler)

	sub, subErr := bus.SubscribeEvidence(func(evt eventbus.EvidenceEvent) {
		certDebouncer.Push(evt)
	})
	if subErr != nil {
		slog.Error("nats subscribe failed", "error", subErr)
		os.Exit(1)
	}
	defer func() { _ = sub.Unsubscribe() }()
	slog.Info("nats evidence subscription active", "subject", eventbus.SubjectEvidence+".>")

	ingestHandler := store.IngestWorker(ctx, stores, pub, ingestTracker, tesseraClient)
	ingestCC, ingestCCErr := bus.ConsumeIngest(ctx, ingestHandler)
	if ingestCCErr != nil {
		slog.Error("jetstream ingest consumer failed", "error", ingestCCErr)
		os.Exit(1)
	}
	defer ingestCC.Stop()

	authHandler := auth.NewHandler()
	authHandler.SetUserStore(pgClient)

	slog.Info("auth: OAuth2 Proxy handles OIDC externally, gateway trusts X-Forwarded-* headers")

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

	subsystems := map[string]pgstore.Pinger{
		"postgres": pgClient,
	}
	e.Use(echo.WrapMiddleware(pgstore.DegradedMiddleware(subsystems)))

	authHandler.Register(e)
	e.Use(authHandler.Middleware())
	e.Use(writeProtect(auth.RequireWrite(pgClient)))

	e.GET("/healthz", func(c echo.Context) error {
		if err := pgClient.Ping(c.Request().Context()); err != nil {
			return c.String(http.StatusServiceUnavailable, "postgres unreachable")
		}
		return c.String(http.StatusOK, "ok")
	})

	apiGroup := e.Group("/api")
	apiGroup.Use(middleware.BodyLimit(fmt.Sprintf("%dM", consts.MaxRequestBody>>20)))
	store.Register(apiGroup, stores)
	authHandler.RegisterUserAPI(apiGroup)
	config.Register(apiGroup, config.Options{
		Values: map[string]string{
			"github_org":        cfg.GitHubOrg,
			"github_repo":       cfg.GitHubRepo,
			"registry_insecure": strconv.FormatBool(cfg.RegistryInsecure),
		},
	})

	apiGroup.GET("/system-info", func(c echo.Context) error {
		authProvider := "OAuth2 Proxy (external)"
		if !cfg.OAuth2ProxyEnabled {
			authProvider = "none (dev mode)"
		}
		dbStatus := "connected"
		if err := pgClient.Ping(c.Request().Context()); err != nil {
			dbStatus = "unreachable"
		}
		return c.JSON(http.StatusOK, map[string]any{
			"version":       cfg.StudioVersion,
			"database":      "PostgreSQL — " + dbStatus,
			"auth_provider": authProvider,
		})
	})

	slog.Info("api routes registered", "groups", []string{"store", "users", "config"})

	wbTarget, err := url.Parse(cfg.WorkbenchURL)
	if err != nil {
		slog.Error("invalid WORKBENCH_URL", "url", cfg.WorkbenchURL, "error", err)
		os.Exit(1)
	}
	wbProxy := nethttputil.NewSingleHostReverseProxy(wbTarget)
	wbProxy.FlushInterval = -1
	wbProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("workbench proxy error", "path", r.URL.Path, "error", err)
		httputil.WriteJSON(w, http.StatusBadGateway, map[string]string{
			"error": "workbench unreachable",
		})
	}
	e.Any("/workbench/*", echo.WrapHandler(wbProxy))
	slog.Info("workbench proxy registered", "upstream", cfg.WorkbenchURL)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(shutdownCtx)
	}()

	addr := net.JoinHostPort(cfg.ListenHost, cfg.Port)

	e.Server.ReadTimeout = consts.ServerReadTimeout
	e.Server.WriteTimeout = consts.ServerWriteTimeout
	e.Server.IdleTimeout = consts.ServerIdleTimeout
	e.Server.MaxHeaderBytes = 1 << 20

	slog.Info("gateway starting", "addr", addr)
	if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
		slog.Error("http server failed", "error", err)
		os.Exit(1)
	}
}

// writeProtect gates POST/PUT/PATCH/DELETE on /api/* through adminGuard.
// GET and non-API requests pass through.
func writeProtect(adminGuard echo.MiddlewareFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		guarded := adminGuard(next)
		return func(c echo.Context) error {
			path := c.Request().URL.Path
			method := c.Request().Method

			if strings.HasPrefix(path, "/api/") && method != http.MethodGet {
				if path == "/api/bootstrap" {
					return next(c)
				}
				return guarded(c)
			}
			return next(c)
		}
	}
}

// buildCertifierPipeline constructs the certifier pipeline from pre-loaded config slices.
func buildCertifierPipeline(registries, engines []string) *certify.Pipeline {
	knownRegistries := make(map[string]bool, len(registries))
	for _, r := range registries {
		knownRegistries[r] = true
	}
	knownEngines := make(map[string]bool, len(engines))
	for _, e := range engines {
		knownEngines[e] = true
	}
	return certify.NewPipeline(
		&certify.SchemaCertifier{},
		&certify.ProvenanceCertifier{KnownRegistries: knownRegistries},
		&certify.ExecutorCertifier{KnownEngines: knownEngines},
	)
}

// certificationAdapter bridges store.Store to certify.CertificationQuerier
// and certify.CertificationWriter.
type certificationAdapter struct {
	store interface {
		QueryRecentEvidence(
			ctx context.Context, policyID string, since time.Time,
		) ([]evidence.EvidenceRowLite, error)
		InsertTrustSignals(ctx context.Context, signals []certify.TrustSignalRow) error
	}
}

func (a *certificationAdapter) QueryRecentEvidence(
	ctx context.Context, policyID string, since time.Time,
) ([]certify.EvidenceRow, error) {
	rows, err := a.store.QueryRecentEvidence(ctx, policyID, since)
	if err != nil {
		return nil, err
	}
	out := make([]certify.EvidenceRow, len(rows))
	for i, r := range rows {
		out[i] = certify.EvidenceRow{
			EvidenceID:       r.EvidenceID,
			TargetID:         r.TargetID,
			RuleID:           r.RuleID,
			EvalResult:       r.EvalResult,
			ComplianceStatus: r.ComplianceStatus,
			EngineName:       r.EngineName,
			SourceRegistry:   r.SourceRegistry,
			AttestationRef:   r.AttestationRef,
			CollectedAt:      r.CollectedAt,
		}
	}
	return out, nil
}

func (a *certificationAdapter) InsertTrustSignals(
	ctx context.Context, signals []certify.TrustSignalRow,
) error {
	return a.store.InsertTrustSignals(ctx, signals)
}
