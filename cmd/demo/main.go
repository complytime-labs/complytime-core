// SPDX-License-Identifier: Apache-2.0

// demo boots an interactive ingest pipeline demo with embedded NATS,
// in-memory Tessera, and inline JWT generation. Run it, then curl
// requests from another terminal and watch CloudEvents appear.
//
// NOT for production use.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	listen := ":8080"
	if v := os.Getenv("DEMO_LISTEN"); v != "" {
		listen = v
	}
	issuer := fmt.Sprintf("http://localhost%s", listen)

	// ── Embedded NATS ─────────────────────────────────────────────────
	ns, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1,
		NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: os.TempDir() + "/complytime-demo-nats",
	})
	if err != nil {
		slog.Error("nats server failed", "error", err)
		os.Exit(1)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		slog.Error("nats not ready")
		os.Exit(1)
	}
	defer ns.Shutdown()

	nbus, err := bus.Connect(ns.ClientURL(), "https://complytime.dev/core")
	if err != nil {
		slog.Error("nats connect failed", "error", err)
		os.Exit(1)
	}
	defer nbus.Close()

	if err := nbus.EnsureIngestStream(ctx, bus.IngestStreamConfig{}); err != nil {
		slog.Error("jetstream setup failed", "error", err)
		os.Exit(1)
	}

	// ── NATS KV stores ────────────────────────────────────────────────
	js := nbus.JetStream()
	targetStore, err := bus.NewTargetStoreKV(ctx, js)
	if err != nil {
		slog.Error("target store failed", "error", err)
		os.Exit(1)
	}
	pubTrust, err := bus.NewPublisherTrustKV(ctx, js)
	if err != nil {
		slog.Error("publisher trust store failed", "error", err)
		os.Exit(1)
	}

	// ── JWT key pair ──────────────────────────────────────────────────
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("keygen failed", "error", err)
		os.Exit(1)
	}
	pubKey, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		slog.Error("jwk failed", "error", err)
		os.Exit(1)
	}
	_ = pubKey.Set(jwk.KeyIDKey, "demo-key")
	_ = pubKey.Set(jwk.AlgorithmKey, jwa.ES256)
	keySet := jwk.NewSet()
	_ = keySet.AddKey(pubKey)

	verifier := auth.NewJWTVerifier(ctx, []string{issuer}, "complytime")

	// ── In-memory Tessera ─────────────────────────────────────────────
	tessera := &memTessera{}

	// ── Stores ────────────────────────────────────────────────────────
	tracker := store.NewIngestTracker()
	stores := store.Stores{
		Targets:           targetStore,
		TrustedPublishers: pubTrust,
		EventPublisher:    nbus,
		IngestTracker:     tracker,
		IngestPublisher:   nbus,
		TesseraAppender:   tessera,
		JWTVerifier:       verifier,
		Authorizer:        &permitAll{},
	}

	// ── JetStream worker ──────────────────────────────────────────────
	worker := store.IngestWorker(ctx, stores, nbus, tracker, tessera)
	cc, err := nbus.ConsumeIngest(ctx, worker)
	if err != nil {
		slog.Error("worker start failed", "error", err)
		os.Exit(1)
	}
	defer cc.Stop()

	// ── Event subscriber (pretty-prints CloudEvents) ──────────────────
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		slog.Error("subscriber connect failed", "error", err)
		os.Exit(1)
	}
	defer nc.Close()

	_, _ = nc.Subscribe("core.>", func(msg *nats.Msg) {
		var raw json.RawMessage
		if err := json.Unmarshal(msg.Data, &raw); err != nil {
			return
		}
		pretty, _ := json.MarshalIndent(raw, "  ", "  ")
		fmt.Printf("\n\033[36m──── %s ────\033[0m\n  %s\n", msg.Subject, pretty)
	})

	// ── HTTP server ───────────────────────────────────────────────────
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Demo token endpoint
	e.GET("/demo/token", func(c echo.Context) error {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": issuer,
			"sub": "demo-publisher",
			"aud": "complytime",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "demo-key"
		signed, err := token.SignedString(privateKey)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.String(http.StatusOK, signed)
	})

	// Demo JWKS endpoint (JWT verifier discovers this via issuer URL)
	e.GET("/.well-known/jwks.json", func(c echo.Context) error {
		return c.JSON(http.StatusOK, keySet)
	})

	// API routes
	store.Register(e.Group("/api"), stores)

	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// ── Banner ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  \033[1mComplyTime Ingest Pipeline Demo\033[0m")
	fmt.Println("  \033[90m───────────────────────────────\033[0m")
	fmt.Printf("  HTTP:   http://localhost%s\n", listen)
	fmt.Println("  Events: watching core.> ...")
	fmt.Println()
	fmt.Println("  \033[33m1. Register a target:\033[0m")
	fmt.Printf("     TOKEN=$(curl -s http://localhost%s/demo/token)\n", listen)
	fmt.Printf("     curl -X POST http://localhost%s/api/admin/targets \\\n", listen)
	fmt.Println("       -H \"Authorization: Bearer $TOKEN\" \\")
	fmt.Println("       -H \"Content-Type: application/yaml\" \\")
	fmt.Println("       --data-binary @examples/demo-target.yaml")
	fmt.Println()
	fmt.Println("  \033[33m2. Submit evidence:\033[0m")
	fmt.Printf("     curl -X POST http://localhost%s/api/ingest \\\n", listen)
	fmt.Println("       -H \"Authorization: Bearer $TOKEN\" \\")
	fmt.Println("       -H \"Content-Type: application/yaml\" \\")
	fmt.Println("       --data-binary @examples/demo-evidence.yaml")
	fmt.Println()
	fmt.Println("  \033[90mWaiting for events...\033[0m")
	fmt.Println()

	// ── Start ─────────────────────────────────────────────────────────
	go func() {
		if err := e.Start(listen); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n  Shutting down...")
	_ = e.Shutdown(context.Background())
}

// ── Helpers ───────────────────────────────────────────────────────────────

type memTessera struct {
	mu      sync.Mutex
	entries [][]byte
}

func (t *memTessera) Add(_ context.Context, data []byte) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := uint64(len(t.entries))
	t.entries = append(t.entries, append([]byte{}, data...))
	return idx, nil
}

func (t *memTessera) Read(_ context.Context, index uint64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if index >= uint64(len(t.entries)) {
		return nil, fmt.Errorf("index %d not found", index)
	}
	return t.entries[index], nil
}

type permitAll struct{}

func (p *permitAll) IsAuthorized(_ cedar.EntityUID, _ map[string]cedar.Value, _ cedar.EntityUID, _ cedar.EntityUID, _ map[string]cedar.Value) (bool, error) {
	return true, nil
}
