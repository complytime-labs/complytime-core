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
	eventbus "github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/certify"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/complytime-labs/complytime-core/internal/tessera"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	natsserver "github.com/nats-io/nats-server/v2/server"
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

// startTestNATSServer creates an embedded NATS server with JetStream enabled.
func startTestNATSServer(t testingHelper) *natsserver.Server {
	t.Helper()

	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1, // Random port
		NoLog:     true,
		NoSigs:    true,
		JetStream: true,
		StoreDir:  t.TempDir(),
	}

	ns, err := natsserver.NewServer(opts)
	Expect(err).NotTo(HaveOccurred(), "Failed to create NATS server")

	go ns.Start()

	Eventually(func() bool {
		return ns.ReadyForConnections(1 * time.Second)
	}).WithTimeout(5*time.Second).WithPolling(100*time.Millisecond).Should(BeTrue(), "NATS server did not start")

	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})

	return ns
}

// connectTestNATS creates a NATS connection to the test server
func connectTestNATS(t testingHelper, url string) *eventbus.Bus {
	t.Helper()

	b, err := eventbus.Connect(url)
	Expect(err).NotTo(HaveOccurred(), "Failed to connect to NATS")
	Expect(b).NotTo(BeNil(), "NATS bus is nil")

	t.Cleanup(func() {
		b.Close()
	})

	return b
}

// setupJetStreamWorker creates the JetStream stream/consumer and starts the
// ingest worker.
func setupJetStreamWorker(
	t testingHelper,
	ctx context.Context,
	b *eventbus.Bus,
	stores store.Stores,
	pub store.EventPublisher,
	tracker *store.IngestTracker,
	reader store.TesseraReader,
) {
	t.Helper()

	err := b.EnsureIngestStream(ctx, eventbus.IngestStreamConfig{
		MaxDeliver: 3,
		AckWait:    5 * time.Second,
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to create JetStream stream")

	handler := store.IngestWorker(ctx, stores, pub, tracker, reader)
	cc, err := b.ConsumeIngest(ctx, handler)
	Expect(err).NotTo(HaveOccurred(), "Failed to start JetStream consumer")

	t.Cleanup(func() {
		cc.Stop()
	})
}

// newTestTessera creates an embedded Tessera client with temp storage
func newTestTessera(t testingHelper) *tessera.Client {
	t.Helper()

	tmpDir := t.TempDir()
	opts := tessera.Options{
		CheckpointTime: 100 * time.Millisecond, // Fast checkpoints for E2E tests
		CheckpointSize: 10,                     // Small batch size for E2E tests
	}
	client, err := tessera.NewClient(context.Background(), tmpDir, opts)
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
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(set)
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

// waitForJob uses Gomega Eventually to poll for job completion
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

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: test helper, URL from test server
	Expect(err).NotTo(HaveOccurred())

	var result map[string]any
	err = json.NewDecoder(resp.Body).Decode(&result)
	Expect(err).NotTo(HaveOccurred())

	return resp, result
}

// certificationAdapter bridges store.Store to bus.CertificationQuerier
// and bus.CertificationWriter interfaces. The store uses store-local types
// while the events package uses certify.EvidenceRow and bus.CertificationRow.
type certificationAdapter struct {
	st *store.Store
}

func (a *certificationAdapter) QueryRecentEvidence(
	ctx context.Context, policyID string, since time.Time,
) ([]certify.EvidenceRow, error) {
	rows, err := a.st.QueryRecentEvidence(ctx, policyID, since)
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
			EnrichmentStatus: r.EnrichmentStatus,
			CollectedAt:      r.CollectedAt,
		}
	}
	return out, nil
}

func (a *certificationAdapter) InsertTrustSignals(
	ctx context.Context, signals []eventbus.TrustSignalRow,
) error {
	// Convert eventbus.TrustSignalRow to store.TrustSignalRow
	storeSignals := make([]store.TrustSignalRow, len(signals))
	for i, s := range signals {
		storeSignals[i] = store.TrustSignalRow{
			EvidenceID: s.EvidenceID,
			Layer:      s.Layer,
			CheckName:  s.CheckName,
			Result:     certify.Result(s.Result),
			Reason:     s.Reason,
			CheckedAt:  s.CheckedAt,
		}
	}
	return a.st.InsertTrustSignals(ctx, storeSignals)
}

// setupCertificationPipeline wires the certifier pipeline (schema + executor)
// to evidence events on the NATS bus with a fast 100ms debounce for E2E tests.
// The ProvenanceCertifier is omitted because the EvaluationLog flattener does
// not populate source_registry or attestation_ref from YAML, so provenance
// would always fail. Tests that need provenance certification should set
// source_registry directly in the DB before triggering the pipeline.
func setupCertificationPipeline(st *store.Store, b *eventbus.Bus) {
	pipeline := certify.NewPipeline(
		&certify.SchemaCertifier{},
		&certify.ExecutorCertifier{KnownEngines: map[string]bool{"test-engine": true}},
	)
	adapter := &certificationAdapter{st: st}
	handler := eventbus.CertificationHandler(context.Background(), pipeline, adapter, adapter)
	debouncer := eventbus.NewDebouncer(100*time.Millisecond, handler)
	_, _ = b.SubscribeEvidence(func(evt eventbus.EvidenceEvent) {
		debouncer.Push(evt)
	})
}
