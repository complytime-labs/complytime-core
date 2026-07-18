package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	listenAddr := os.Getenv("TESTJWKS_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8888"
	}

	tokenDir := os.Getenv("TOKEN_DIR")
	if tokenDir == "" {
		tokenDir = "/tokens"
	}

	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://testjwks:8888"
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("failed to generate key", "error", err)
		os.Exit(1)
	}

	pubKey, err := jwk.Import(pub)
	if err != nil {
		slog.Error("failed to import public key", "error", err)
		os.Exit(1)
	}
	if err := pubKey.Set(jwk.KeyIDKey, "testjwks-1"); err != nil {
		slog.Error("failed to set key ID", "error", err)
		os.Exit(1)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		slog.Error("failed to set algorithm", "error", err)
		os.Exit(1)
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		slog.Error("failed to add key to set", "error", err)
		os.Exit(1)
	}

	// Write service tokens
	tokens := []struct {
		filename string
		sub      string
		audience string
		admin    bool
		service  bool
	}{
		{"gateway-token", "gateway-worker", "complytime-locker", true, true},
		{"graph-token", "graph-loader", "complytime-locker", false, true},
	}

	for _, t := range tokens {
		if err := writeToken(priv, issuerURL, t.sub, t.audience, t.admin, t.service, filepath.Join(tokenDir, t.filename)); err != nil {
			slog.Error("failed to write token", "file", t.filename, "error", err)
			os.Exit(1)
		}
		slog.Info("wrote service token", "file", t.filename, "sub", t.sub)
	}

	// Refresh tokens periodically
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			for _, t := range tokens {
				if err := writeToken(priv, issuerURL, t.sub, t.audience, t.admin, t.service, filepath.Join(tokenDir, t.filename)); err != nil {
					slog.Warn("failed to refresh token", "file", t.filename, "error", err)
				}
			}
			slog.Info("refreshed service tokens")
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("POST /mint", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Sub      string   `json:"sub"`
			Audience []string `json:"audience"`
			Admin    bool     `json:"admin"`
			Service  bool     `json:"service"`
			TTL      string   `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Sub == "" {
			http.Error(w, "sub is required", http.StatusBadRequest)
			return
		}
		if len(req.Audience) == 0 {
			req.Audience = []string{"complytime-gateway"}
		}

		ttl := time.Hour
		if req.TTL != "" {
			parsed, err := time.ParseDuration(req.TTL)
			if err != nil {
				http.Error(w, "invalid ttl", http.StatusBadRequest)
				return
			}
			ttl = parsed
		}

		tok, err := jwt.NewBuilder().
			Issuer(issuerURL).
			Subject(req.Sub).
			Audience(req.Audience).
			IssuedAt(time.Now()).
			Expiration(time.Now().Add(ttl)).
			Claim("admin", req.Admin).
			Claim("service", req.Service).
			Build()
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to build token: %v", err), http.StatusInternalServerError)
			return
		}

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), priv))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to sign token: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": string(signed)})
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("starting testjwks server", "addr", listenAddr)

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
		slog.Info("shutting down")
	case err := <-errCh:
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}

func writeToken(priv ed25519.PrivateKey, issuer, sub, audience string, admin, service bool, path string) error {
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1*time.Hour)).
		Claim("admin", admin).
		Claim("service", service).
		Build()
	if err != nil {
		return fmt.Errorf("building token: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), priv))
	if err != nil {
		return fmt.Errorf("signing token: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("creating token dir: %w", err)
	}

	return os.WriteFile(path, signed, 0600)
}
