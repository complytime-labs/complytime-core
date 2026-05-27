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
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/blob"
	"github.com/complytime-labs/complytime-core/internal/certifier"
	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	pgstore "github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := httputil.EnvOr("PORT", "8080")

	pgCfg, ok := pgstore.ConfigFromEnv()
	if !ok {
		slog.Error("POSTGRES_URL is required")
		os.Exit(1)
	}
	pgClient, err := pgstore.New(ctx, pgCfg)
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
	if cfg, ok := blob.ConfigFromEnv(); ok {
		if cfg.AccessKey == "" || cfg.SecretKey == "" {
			slog.Error("blob storage enabled but BLOB_ACCESS_KEY / BLOB_SECRET_KEY missing")
			os.Exit(1)
		}
		bs, err := blob.NewMinioBlobStore(ctx, cfg)
		if err != nil {
			slog.Error("blob storage init failed", "error", err)
			os.Exit(1)
		}
		blobStore = bs
		slog.Info("blob storage configured", "endpoint", cfg.Endpoint, "bucket", cfg.Bucket)
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

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		slog.Error("NATS_URL is required — event bus drives the certification pipeline")
		os.Exit(1)
	}
	bus, busErr := events.Connect(natsURL)
	if busErr != nil {
		slog.Error("nats connection failed", "error", busErr)
		os.Exit(1)
	}
	defer bus.Close()
	slog.Info("nats ready")

	var pub store.EventPublisher = bus
	ingestTracker := store.NewIngestTracker()

	// Initialize Tessera client for transparency log
	tesseraPath := httputil.EnvOr("TESSERA_PATH", "/data/tessera")
	tesseraClient, err := tessera.NewClient(ctx, tesseraPath, tessera.DefaultOptions())
	if err != nil {
		slog.Error("tessera client init failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := tesseraClient.Close(); err != nil {
			slog.Warn("tessera client close failed", "error", err)
		}
	}()
	slog.Info("tessera client ready", "path", tesseraPath)

	// Initialize JWT verifier with allowed issuers from environment
	allowedIssuers := splitComma(os.Getenv("JWT_ISSUERS"))
	if len(allowedIssuers) == 0 {
		slog.Warn("JWT_ISSUERS not configured — trusted publisher ingestion will be unavailable")
	}
	jwtVerifier := auth.NewJWTVerifier(ctx, allowedIssuers)
	slog.Info("jwt verifier ready", "allowed_issuers", len(allowedIssuers))

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
	}
	slog.Info("store API registered", "routes", []string{
		"/api/policies",
		"/api/ingest",
		"/api/ingest/jobs/:job_id",
		"/api/audit-logs",
		"/api/mappings",
	})

	pipeline := buildCertifierPipeline()
	certAdapter := &certificationAdapter{store: st}
	certHandler := events.CertificationHandler(ctx, pipeline, certAdapter, certAdapter)
	certDebouncer := events.NewDebouncer(consts.EventDebounceDuration, certHandler)

	sub, subErr := bus.SubscribeEvidence(func(evt events.EvidenceEvent) {
		certDebouncer.Push(evt)
	})
	if subErr != nil {
		slog.Error("nats subscribe failed", "error", subErr)
		os.Exit(1)
	}
	defer func() { _ = sub.Unsubscribe() }()
	slog.Info("nats evidence subscription active", "subject", events.SubjectEvidence+".>")

	ingestWorker := store.IngestWorker(ctx, stores, pub, ingestTracker)
	ingestSub, ingestSubErr := bus.SubscribeIngestRaw(ingestWorker)
	if ingestSubErr != nil {
		slog.Error("nats ingest subscribe failed", "error", ingestSubErr)
		os.Exit(1)
	}
	defer func() { _ = ingestSub.Unsubscribe() }()
	slog.Info("nats async ingest subscription active", "subject", events.SubjectIngestRaw)

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

	if origins := splitComma(os.Getenv("CORS_ORIGINS")); len(origins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins:     origins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
			MaxAge:           consts.CORSMaxAgeSecs,
		}))
		slog.Info("CORS enabled", "origins", origins)
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
			"github_org":        httputil.EnvOr("GITHUB_ORG", ""),
			"github_repo":       httputil.EnvOr("GITHUB_REPO", "complytime-studio"),
			"registry_insecure": httputil.EnvOr("REGISTRY_INSECURE", ""),
		},
	})

	apiGroup.GET("/system-info", func(c echo.Context) error {
		authProvider := "OAuth2 Proxy (external)"
		if os.Getenv("OAUTH2_PROXY_ENABLED") == "false" {
			authProvider = "none (dev mode)"
		}
		dbStatus := "connected"
		if err := pgClient.Ping(c.Request().Context()); err != nil {
			dbStatus = "unreachable"
		}
		return c.JSON(http.StatusOK, map[string]any{
			"version":       httputil.EnvOr("STUDIO_VERSION", "dev"),
			"database":      "PostgreSQL — " + dbStatus,
			"auth_provider": authProvider,
		})
	})

	slog.Info("api routes registered", "groups", []string{"store", "users", "config"})

	workbenchURL := httputil.EnvOr("WORKBENCH_URL", "http://studio-workbench:8090")
	wbTarget, err := url.Parse(workbenchURL)
	if err != nil {
		slog.Error("invalid WORKBENCH_URL", "url", workbenchURL, "error", err)
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
	slog.Info("workbench proxy registered", "upstream", workbenchURL)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(shutdownCtx)
	}()

	listenHost := httputil.EnvOr("LISTEN_HOST", "0.0.0.0")
	addr := net.JoinHostPort(listenHost, port)

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

func splitComma(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
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

// buildCertifierPipeline constructs the certifier pipeline from environment.
func buildCertifierPipeline() *certifier.Pipeline {
	knownRegistries := make(map[string]bool)
	for _, r := range splitComma(os.Getenv("KNOWN_REGISTRIES")) {
		knownRegistries[r] = true
	}
	knownEngines := make(map[string]bool)
	for _, e := range splitComma(os.Getenv("KNOWN_ENGINES")) {
		knownEngines[e] = true
	}
	return certifier.NewPipeline(
		&certifier.SchemaCertifier{},
		&certifier.ProvenanceCertifier{KnownRegistries: knownRegistries},
		&certifier.ExecutorCertifier{KnownEngines: knownEngines},
	)
}

// certificationAdapter bridges store.Store to events.CertificationQuerier
// and events.CertificationWriter.
type certificationAdapter struct {
	store interface {
		QueryRecentEvidence(
			ctx context.Context, policyID string, since time.Time,
		) ([]store.EvidenceRowLite, error)
		InsertCertifications(ctx context.Context, rows []store.CertificationRow) error
		UpdateEvidenceCertified(ctx context.Context, evidenceID string, certified bool) error
	}
}

func (a *certificationAdapter) QueryRecentEvidence(
	ctx context.Context, policyID string, since time.Time,
) ([]certifier.EvidenceRow, error) {
	rows, err := a.store.QueryRecentEvidence(ctx, policyID, since)
	if err != nil {
		return nil, err
	}
	out := make([]certifier.EvidenceRow, len(rows))
	for i, r := range rows {
		out[i] = certifier.EvidenceRow{
			EvidenceID:       r.EvidenceID,
			TargetID:         r.TargetID,
			RuleID:           r.RuleID,
			EvalResult:       r.EvalResult,
			ComplianceStatus: r.ComplianceStatus,
			EngineName:       r.EngineName,
			SourceRegistry:   r.SourceRegistry,
			AttestationRef:   r.AttestationRef,
			EnrichmentStatus: r.EnrichmentStatus,
			CollectedAt:      r.CollectedAt,
		}
	}
	return out, nil
}

func (a *certificationAdapter) InsertCertifications(
	ctx context.Context, rows []events.CertificationRow,
) error {
	storeRows := make([]store.CertificationRow, len(rows))
	for i, r := range rows {
		storeRows[i] = store.CertificationRow{
			EvidenceID:       r.EvidenceID,
			Certifier:        r.Certifier,
			CertifierVersion: r.CertifierVersion,
			Result:           r.Result,
			Reason:           r.Reason,
		}
	}
	return a.store.InsertCertifications(ctx, storeRows)
}

func (a *certificationAdapter) UpdateEvidenceCertified(
	ctx context.Context, evidenceID string, certified bool,
) error {
	return a.store.UpdateEvidenceCertified(ctx, evidenceID, certified)
}
