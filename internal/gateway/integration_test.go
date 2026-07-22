//go:build integration

package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authz"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway"
	"github.com/complytime-labs/complytime-core/internal/ingest"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

// TestGatewayIngest tests the simplified gateway flow:
// - Submit artifact → get 202 with jobId
// - Job status starts as pending (via NATS KV)
// - Verify receipt was published to JetStream
func TestGatewayIngest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start embedded NATS server
	ns, js := startEmbeddedNATS(t)
	defer ns.Shutdown()

	// Ensure NATS infrastructure
	err := natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Create JWT test keys and auth
	privateKey, jwtAuth, issuer := createTestJWTAuth(t)

	// Create trust store
	trustStore, err := trust.NewTrustStore(js)
	require.NoError(t, err)

	// Register a subject in the trust store
	subjectID := "test-subject-gateway"
	sub := "test-publisher"

	err = trustStore.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	err = trustStore.SetPublisherTrust(ctx, subjectID, []trust.TrustEntry{
		{Issuer: issuer, Sub: sub},
	})
	require.NoError(t, err)

	// Get NATS connection from server
	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-test")

	policySet, err := authz.LoadEmbeddedPolicies()
	require.NoError(t, err)

	// Load Gemara schemas
	schemas, err := gateway.NewSchemaRegistry()
	require.NoError(t, err)

	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, schemas)

	// Build gateway router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authn.AuthMiddleware(jwtAuth))
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted))

		r.Post("/api/ingest", gwHandler.IngestArtifact)
	})

	gatewayServer := httptest.NewServer(r)
	defer gatewayServer.Close()

	// Test flow begins

	// 1. Submit artifact
	artifact := map[string]interface{}{
		"type":      "test-artifact",
		"target":    map[string]string{"id": subjectID},
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      "gateway integration test",
	}

	token := createTestJWT(t, privateKey, issuer, sub)
	ingestResp := makeAuthenticatedRequestWithSubject(t, gatewayServer.URL+"/api/ingest", "POST", token, subjectID, artifact)
	require.Equal(t, http.StatusAccepted, ingestResp.StatusCode)

	var ingestResult gateway.IngestResponse
	err = json.NewDecoder(ingestResp.Body).Decode(&ingestResult)
	require.NoError(t, err)
	require.NotEmpty(t, ingestResult.JobId)

	// 2. Verify IngestRef was published to JetStream
	jobID := ingestResult.JobId
	consumer, err := js.CreateOrUpdateConsumer(ctx, natsinfra.StreamIngest, jetstream.ConsumerConfig{
		FilterSubject: natsinfra.SubjectIngest,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	require.NoError(t, err)

	msgs, err := consumer.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
	require.NoError(t, err)

	msg := <-msgs.Messages()
	require.NotNil(t, msg)

	var ingestRef ingest.IngestRef
	err = json.Unmarshal(msg.Data(), &ingestRef)
	require.NoError(t, err)
	assert.Equal(t, jobID.String(), ingestRef.JobID)
	assert.Equal(t, subjectID, ingestRef.SubjectID)
	assert.NotEmpty(t, ingestRef.ContentDigest)
	assert.NotEmpty(t, ingestRef.ReceiptBytes)
}

// TestGatewayDSSE tests DSSE artifact submission
func TestGatewayDSSE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start embedded NATS server
	ns, js := startEmbeddedNATS(t)
	defer ns.Shutdown()

	// Ensure NATS infrastructure
	err := natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Create JWT test keys and auth
	privateKey, jwtAuth, issuer := createTestJWTAuth(t)

	// Create trust store
	trustStore, err := trust.NewTrustStore(js)
	require.NoError(t, err)

	// Register a subject in the trust store
	subjectID := "test-subject-dsse"
	sub := "test-publisher"

	err = trustStore.RegisterSubject(ctx, subjectID)
	require.NoError(t, err)

	err = trustStore.SetPublisherTrust(ctx, subjectID, []trust.TrustEntry{
		{Issuer: issuer, Sub: sub},
	})
	require.NoError(t, err)

	// Get NATS connection from server
	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-test")

	policySet, err := authz.LoadEmbeddedPolicies()
	require.NoError(t, err)

	// Load Gemara schemas
	schemas, err := gateway.NewSchemaRegistry()
	require.NoError(t, err)

	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, schemas)

	// Build gateway router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authn.AuthMiddleware(jwtAuth))
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted))

		r.Post("/api/ingest", gwHandler.IngestArtifact)
	})

	gatewayServer := httptest.NewServer(r)
	defer gatewayServer.Close()

	// Test DSSE submission
	dsseEnvelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     "eyJ0ZXN0IjogImRzc2UgaW50ZWdyYXRpb24ifQ==",
		"signatures": []map[string]string{
			{"sig": "test-signature"},
		},
	}

	dsseJSON, err := json.Marshal(dsseEnvelope)
	require.NoError(t, err)

	token := createTestJWT(t, privateKey, issuer, sub)

	req, err := http.NewRequest("POST", gatewayServer.URL+"/api/ingest", bytes.NewReader(dsseJSON))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/vnd.dsse+json")
	req.Header.Set("X-Subject-ID", subjectID)
	req.Header.Set("Authorization", "Bearer "+token)

	ingestResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer ingestResp.Body.Close()

	require.Equal(t, http.StatusAccepted, ingestResp.StatusCode)

	var ingestResult gateway.IngestResponse
	err = json.NewDecoder(ingestResp.Body).Decode(&ingestResult)
	require.NoError(t, err)
	require.NotEmpty(t, ingestResult.JobId, "Gateway should return a job ID for correlation")
}

// Helper functions

func startEmbeddedNATS(t *testing.T) (*server.Server, jetstream.JetStream) {
	t.Helper()

	opts := &server.Options{
		JetStream: true,
		StoreDir:  t.TempDir(),
		Port:      -1, // random port
	}

	ns, err := server.NewServer(opts)
	require.NoError(t, err)

	go ns.Start()
	require.True(t, ns.ReadyForConnections(10*time.Second))

	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)

	js, err := jetstream.New(nc)
	require.NoError(t, err)

	return ns, js
}

func createTestJWTAuth(t *testing.T) (*ecdsa.PrivateKey, *authn.JWTAuthenticator, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Serve JWKS
	jwks := jwk.NewSet()
	key, err := jwk.Import(privateKey.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256()))
	require.NoError(t, jwks.AddKey(key))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks)
		} else {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(jwksServer.Close)

	auth, err := authn.NewJWTAuthenticator(context.Background(), []string{jwksServer.URL}, "complytime-gateway")
	require.NoError(t, err)

	return privateKey, auth, jwksServer.URL
}

func createTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey, issuer, sub string) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{"complytime-gateway"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1*time.Hour)).
		Claim("admin", false).
		Build()
	require.NoError(t, err)

	// Sign with key ID matching the JWKS key
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256()))

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)

	return string(signed)
}

func makeAuthenticatedRequestWithSubject(t *testing.T, url, method, token, subjectID string, body interface{}) *http.Response {
	t.Helper()

	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(method, url, bytes.NewReader(bodyJSON))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Subject-ID", subjectID)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	return resp
}

func makeAuthenticatedRequestNoBody(t *testing.T, url, method, token string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	return resp
}
