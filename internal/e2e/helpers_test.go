// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/gomega"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/labstack/echo/v4"
)

// testingHelper is an interface satisfied by both *testing.T and GinkgoT().
// It covers the methods used by our helper functions.
type testingHelper interface {
	Helper()
	Cleanup(func())
	TempDir() string
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	FailNow()
	Logf(format string, args ...any)
}

// startTestNATSServer creates an embedded NATS server for testing
func startTestNATSServer(t testingHelper) *natsserver.Server {
	t.Helper()

	opts := &natsserver.Options{
		Host:   "127.0.0.1",
		Port:   -1, // Random port
		NoLog:  true,
		NoSigs: true,
	}

	ns, err := natsserver.NewServer(opts)
	Expect(err).NotTo(HaveOccurred(), "Failed to create NATS server")

	// Start server in goroutine
	go ns.Start()

	// Wait for server to be ready
	Eventually(func() bool {
		return ns.ReadyForConnections(1 * time.Second)
	}).WithTimeout(5 * time.Second).WithPolling(100 * time.Millisecond).Should(BeTrue(), "NATS server did not start")

	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})

	return ns
}

// connectTestNATS creates a NATS connection to the test server
func connectTestNATS(t testingHelper, url string) *events.Bus {
	t.Helper()

	bus, err := events.Connect(url)
	Expect(err).NotTo(HaveOccurred(), "Failed to connect to NATS")
	Expect(bus).NotTo(BeNil(), "NATS bus is nil")

	t.Cleanup(func() {
		bus.Close()
	})

	return bus
}

// newTestTessera creates an embedded Tessera client with temp storage
func newTestTessera(t testingHelper) *tessera.Client {
	t.Helper()

	tmpDir := t.TempDir()
	client, err := tessera.NewClient(context.Background(), tmpDir, tessera.DefaultOptions())
	Expect(err).NotTo(HaveOccurred(), "Failed to create Tessera client")

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client
}

// jwtTestContext holds JWT testing infrastructure
type jwtTestContext struct {
	PrivateKey *ecdsa.PrivateKey
	IssuerURL  string
	Verifier   *auth.JWTVerifier
	Server     *httptest.Server
}

// newTestJWTVerifier creates a mock JWT verifier with JWKS endpoint
func newTestJWTVerifier(t testingHelper) *jwtTestContext {
	t.Helper()

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred(), "Failed to generate ECDSA key")

	// Create JWK from public key
	key, err := jwk.FromRaw(privateKey.PublicKey)
	Expect(err).NotTo(HaveOccurred(), "Failed to create JWK")

	err = key.Set(jwk.KeyIDKey, "test-key-id")
	Expect(err).NotTo(HaveOccurred())

	err = key.Set(jwk.AlgorithmKey, jwa.ES256)
	Expect(err).NotTo(HaveOccurred())

	// Create JWKS set
	set := jwk.NewSet()
	_ = set.AddKey(key)

	// Create JWKS endpoint
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks" {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]any{
				"keys": set,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.NotFound(w, r)
	}))

	t.Cleanup(jwksServer.Close)

	issuerURL := jwksServer.URL
	verifier := auth.NewJWTVerifier(context.Background(), []string{issuerURL}, "")

	return &jwtTestContext{
		PrivateKey: privateKey,
		IssuerURL:  issuerURL,
		Verifier:   verifier,
		Server:     jwksServer,
	}
}

// generateTestJWT creates a signed JWT token for testing
func (ctx *jwtTestContext) generateTestJWT(t testingHelper, sub string) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": ctx.IssuerURL,
		"sub": sub,
		"aud": "complytime-core",
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"

	signedToken, err := token.SignedString(ctx.PrivateKey)
	Expect(err).NotTo(HaveOccurred(), "Failed to sign JWT")

	return signedToken
}

// waitForJobCompletion polls the tracker until the job completes (legacy helper)
func waitForJobCompletion(t testingHelper, tracker *store.IngestTracker, jobID string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status := tracker.Get(jobID)
		if status != nil && status.Status == "completed" {
			return
		}
		if status != nil && status.Status == "failed" {
			t.Fatalf("Job %s failed: %s", jobID, status.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Job %s did not complete within %v", jobID, timeout)
}

// waitForJob is a Gomega-native alternative using Eventually
func waitForJob(tracker *store.IngestTracker, jobID string) {
	Eventually(func() string {
		status := tracker.Get(jobID)
		if status == nil {
			return ""
		}
		return status.Status
	}).WithTimeout(10 * time.Second).WithPolling(50 * time.Millisecond).Should(
		SatisfyAny(Equal("completed"), Equal("failed")),
	)

	status := tracker.Get(jobID)
	Expect(status).NotTo(BeNil())
	Expect(status.Status).To(Equal("completed"), "Job failed: %s", status.Error)
}

// newTestEchoServer creates an Echo instance for E2E testing
func newTestEchoServer() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	return e
}

// submitEvidence submits evidence YAML to the ingest endpoint
func submitEvidence(t testingHelper, serverURL string, token string, yamlContent []byte) (*http.Response, map[string]any) {
	t.Helper()

	req, err := http.NewRequest("POST", serverURL, bytes.NewReader(yamlContent))
	Expect(err).NotTo(HaveOccurred())

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/x-yaml")

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred())

	var result map[string]any
	err = json.NewDecoder(resp.Body).Decode(&result)
	Expect(err).NotTo(HaveOccurred())

	return resp, result
}
