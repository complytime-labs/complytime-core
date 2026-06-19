// SPDX-License-Identifier: Apache-2.0

// testjwks is a minimal JWKS server for local development and smoke testing.
// It generates an ECDSA P-256 key pair on startup, serves JWKS at
// /.well-known/jwks.json, and issues signed JWTs at /token?sub=<subject>.
// NOT for production use.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/complytime-labs/complytime-core/internal/httputil"
)

func main() {
	listen := httputil.EnvOr("TESTJWKS_LISTEN", ":9090")
	audience := httputil.EnvOr("TESTJWKS_AUDIENCE", "complytime-core")
	issuerOverride := os.Getenv("TESTJWKS_ISSUER")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("failed to generate key", "error", err)
		os.Exit(1)
	}

	key, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		slog.Error("failed to create JWK", "error", err)
		os.Exit(1)
	}
	_ = key.Set(jwk.KeyIDKey, "test-key-id")
	_ = key.Set(jwk.AlgorithmKey, jwa.ES256)

	keySet := jwk.NewSet()
	_ = keySet.AddKey(key)

	slog.Info("testjwks ready", "listen", listen)

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keySet)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		if sub == "" {
			sub = "repo:complytime-labs/complytime-core"
		}

		issuer := issuerOverride
		if issuer == "" {
			issuer = "http://" + r.Host
		}
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": issuer,
			"sub": sub,
			"aud": audience,
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "test-key-id"

		signed, err := token.SignedString(privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(signed))
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	slog.Error("server exited", "error", http.ListenAndServe(listen, nil)) //nolint:gosec
}
