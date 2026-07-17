//go:build integration

package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/complytime-labs/complytime-core/internal/gateway"
	"github.com/complytime-labs/complytime-core/internal/locker"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// TestFullLifecycle tests the complete evidence gateway flow:
// - Start embedded NATS
// - Start locker in-process
// - Start gateway in-process
// - Register subject via admin API
// - Submit unsigned artifact via ingest API
// - Poll until sealed
// - Verify in locker
func TestFullLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Start embedded NATS server
	ns, js := startEmbeddedNATS(t)
	defer ns.Shutdown()

	// Ensure NATS infrastructure
	err := natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Start locker in-process
	lockerDir := t.TempDir()
	lk, err := locker.NewLocker(lockerDir)
	require.NoError(t, err)
	defer lk.Close(ctx)

	lockerHandler := locker.NewHandler(lk, "test-secret")
	lockerServer := httptest.NewServer(lockerHandler)
	defer lockerServer.Close()

	// Create JWT test keys and auth
	privateKey, tokenAuth := createTestJWTAuth(t)

	// Start gateway in-process
	trustStore, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	// Get NATS connection from server
	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	eventPublisher := gateway.NewEventPublisher(nc)

	policySet, err := authz.LoadEmbeddedPolicies()
	require.NoError(t, err)

	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, lockerServer.URL, "test-secret")

	// Build gateway router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(testJWTAuthenticator)
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted))

		r.Post("/api/ingest", gwHandler.IngestArtifact)
		r.Get("/api/ingest/jobs/{jobId}", func(w http.ResponseWriter, r *http.Request) {
			jobIDStr := chi.URLParam(r, "jobId")
			var jobID types.UUID
			err := jobID.UnmarshalText([]byte(jobIDStr))
			if err != nil {
				http.Error(w, "Invalid job ID", http.StatusBadRequest)
				return
			}
			gwHandler.GetJobStatus(w, r, jobID)
		})
		r.Post("/api/admin/subjects", gwHandler.RegisterSubject)
	})

	gatewayServer := httptest.NewServer(r)
	defer gatewayServer.Close()

	// Start worker
	worker := gateway.NewWorker(js, lockerServer.URL, "test-secret", eventPublisher, &gwHandler.Jobs)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	go worker.Start(workerCtx)
	defer worker.Stop()

	// Wait for worker to start
	time.Sleep(100 * time.Millisecond)

	// Test flow begins

	// 1. Register subject
	subjectID := "test-subject-1"
	issuer := "https://test.issuer.example"
	sub := "test-publisher"

	registerReq := gateway.SubjectRegistrationRequest{
		SubjectId: subjectID,
		TrustedPublishers: []gateway.TrustedPublisher{
			{
				Issuer: issuer,
				Sub:    sub,
			},
		},
	}

	token := createTestJWT(t, privateKey, issuer, sub)
	registerResp := makeAuthenticatedRequest(t, gatewayServer.URL+"/api/admin/subjects", "POST", token, registerReq)
	require.Equal(t, http.StatusCreated, registerResp.StatusCode)

	var registerResult gateway.SubjectRegistrationResponse
	err = json.NewDecoder(registerResp.Body).Decode(&registerResult)
	require.NoError(t, err)
	assert.Equal(t, subjectID, registerResult.SubjectId)

	// 2. Submit unsigned artifact
	artifact := map[string]interface{}{
		"type":      "test-artifact",
		"target":    map[string]string{"id": subjectID},
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      "test data",
	}

	ingestResp := makeAuthenticatedRequestWithSubject(t, gatewayServer.URL+"/api/ingest", "POST", token, subjectID, artifact)
	require.Equal(t, http.StatusAccepted, ingestResp.StatusCode)

	var ingestResult gateway.IngestResponse
	err = json.NewDecoder(ingestResp.Body).Decode(&ingestResult)
	require.NoError(t, err)
	require.NotEmpty(t, ingestResult.JobId)

	// 3. Poll until sealed
	jobID := ingestResult.JobId
	var finalStatus gateway.JobStatus
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		statusResp := makeAuthenticatedRequestNoBody(t, gatewayServer.URL+"/api/ingest/jobs/"+jobID.String(), "GET", token)
		if statusResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(statusResp.Body)
			statusResp.Body.Close()
			t.Fatalf("Failed to get job status: %d body=%s", statusResp.StatusCode, string(body))
		}

		err = json.NewDecoder(statusResp.Body).Decode(&finalStatus)
		require.NoError(t, err)

		if finalStatus.Status == gateway.Sealed {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	assert.Equal(t, gateway.Sealed, finalStatus.Status, "Job should be sealed")
	require.NotNil(t, finalStatus.Digest, "Sealed job should have a digest")
	require.NotNil(t, finalStatus.LogIndex, "Sealed job should have a log index")

	// 4. Verify in locker
	verifyURL := fmt.Sprintf("%s/ledgers/%s/verify/%s", lockerServer.URL, subjectID, *finalStatus.Digest)
	verifyReq, err := http.NewRequest("GET", verifyURL, nil)
	require.NoError(t, err)
	verifyReq.Header.Set("Authorization", "Bearer test-secret")
	verifyResp, err := http.DefaultClient.Do(verifyReq)
	require.NoError(t, err)
	defer verifyResp.Body.Close()

	require.Equal(t, http.StatusOK, verifyResp.StatusCode)

	var verifyResult map[string]interface{}
	err = json.NewDecoder(verifyResp.Body).Decode(&verifyResult)
	require.NoError(t, err)
	assert.True(t, verifyResult["found"].(bool), "Digest should be found in locker")
}

// TestDSSELifecycle tests the DSSE artifact flow:
// - Register subject
// - Submit DSSE artifact
// - Verify both DSSE and DSSE channel receipt are sealed
func TestDSSELifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Start embedded NATS server
	ns, js := startEmbeddedNATS(t)
	defer ns.Shutdown()

	// Ensure NATS infrastructure
	err := natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Start locker in-process
	lockerDir := t.TempDir()
	lk, err := locker.NewLocker(lockerDir)
	require.NoError(t, err)
	defer lk.Close(ctx)

	lockerHandler := locker.NewHandler(lk, "test-secret")
	lockerServer := httptest.NewServer(lockerHandler)
	defer lockerServer.Close()

	// Create JWT test keys and auth
	privateKey, tokenAuth := createTestJWTAuth(t)

	// Start gateway in-process
	trustStore, err := gateway.NewTrustStore(js)
	require.NoError(t, err)

	// Get NATS connection from server
	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	eventPublisher := gateway.NewEventPublisher(nc)

	policySet, err := authz.LoadEmbeddedPolicies()
	require.NoError(t, err)

	gwHandler := gateway.NewHandler(trustStore, js, eventPublisher, lockerServer.URL, "test-secret")

	// Build gateway router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/healthz", gwHandler.HealthCheck)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(testJWTAuthenticator)
		r.Use(gateway.SubjectIDExtractor)
		r.Use(authz.Middleware(policySet, trustStore.IsPublisherTrusted))

		r.Post("/api/ingest", gwHandler.IngestArtifact)
		r.Get("/api/ingest/jobs/{jobId}", func(w http.ResponseWriter, r *http.Request) {
			jobIDStr := chi.URLParam(r, "jobId")
			var jobID types.UUID
			err := jobID.UnmarshalText([]byte(jobIDStr))
			if err != nil {
				http.Error(w, "Invalid job ID", http.StatusBadRequest)
				return
			}
			gwHandler.GetJobStatus(w, r, jobID)
		})
		r.Post("/api/admin/subjects", gwHandler.RegisterSubject)
	})

	gatewayServer := httptest.NewServer(r)
	defer gatewayServer.Close()

	// Start worker
	worker := gateway.NewWorker(js, lockerServer.URL, "test-secret", eventPublisher, &gwHandler.Jobs)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	go worker.Start(workerCtx)
	defer worker.Stop()

	// Wait for worker to start
	time.Sleep(100 * time.Millisecond)

	// Test flow begins

	// 1. Register subject
	subjectID := "test-subject-dsse"
	issuer := "https://test.issuer.example"
	sub := "test-publisher"

	registerReq := gateway.SubjectRegistrationRequest{
		SubjectId: subjectID,
		TrustedPublishers: []gateway.TrustedPublisher{
			{
				Issuer: issuer,
				Sub:    sub,
			},
		},
	}

	token := createTestJWT(t, privateKey, issuer, sub)
	registerResp := makeAuthenticatedRequest(t, gatewayServer.URL+"/api/admin/subjects", "POST", token, registerReq)
	require.Equal(t, http.StatusCreated, registerResp.StatusCode)

	// 2. Submit DSSE artifact
	dsseEnvelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     "eyJ0ZXN0IjogImRhdGEifQ==",
		"signatures": []map[string]string{
			{"sig": "test-signature"},
		},
	}

	dsseJSON, err := json.Marshal(dsseEnvelope)
	require.NoError(t, err)

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
	require.NotEmpty(t, ingestResult.JobId)

	// 3. Poll until sealed
	jobID := ingestResult.JobId
	var finalStatus gateway.JobStatus
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		statusResp := makeAuthenticatedRequestNoBody(t, gatewayServer.URL+"/api/ingest/jobs/"+jobID.String(), "GET", token)
		if statusResp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to get job status: %d", statusResp.StatusCode)
		}

		err = json.NewDecoder(statusResp.Body).Decode(&finalStatus)
		require.NoError(t, err)

		if finalStatus.Status == gateway.Sealed {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	assert.Equal(t, gateway.Sealed, finalStatus.Status, "Job should be sealed")
	require.NotNil(t, finalStatus.Digest, "Sealed job should have a digest")

	// 4. Verify DSSE channel receipt is in locker
	verifyURL := fmt.Sprintf("%s/ledgers/%s/verify/%s", lockerServer.URL, subjectID, *finalStatus.Digest)
	verifyReq, err := http.NewRequest("GET", verifyURL, nil)
	require.NoError(t, err)
	verifyReq.Header.Set("Authorization", "Bearer test-secret")
	verifyResp, err := http.DefaultClient.Do(verifyReq)
	require.NoError(t, err)
	defer verifyResp.Body.Close()

	require.Equal(t, http.StatusOK, verifyResp.StatusCode)

	var verifyResult map[string]interface{}
	err = json.NewDecoder(verifyResp.Body).Decode(&verifyResult)
	require.NoError(t, err)
	assert.True(t, verifyResult["found"].(bool), "Channel attestation should be found in locker")
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

func createTestJWTAuth(t *testing.T) (*ecdsa.PrivateKey, *jwtauth.JWTAuth) {
	t.Helper()

	// Create ECDSA key pair for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tokenAuth := jwtauth.New(jwa.ES256().String(), privateKey, privateKey.Public())
	return privateKey, tokenAuth
}

func createTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey, issuer, sub string) string {
	return createTestJWTWithAdmin(t, privateKey, issuer, sub, true)
}

func createTestJWTWithAdmin(t *testing.T, privateKey *ecdsa.PrivateKey, issuer, sub string, isAdmin bool) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(sub).
		Audience([]string{"complytime-gateway"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Hour)).
		Claim("admin", isAdmin).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), privateKey))
	require.NoError(t, err)

	return string(signed)
}

func testJWTAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate audience
		audiences, ok := token.Audience()
		if !ok || len(audiences) == 0 {
			http.Error(w, "Unauthorized: missing audience", http.StatusUnauthorized)
			return
		}
		audFound := false
		for _, aud := range audiences {
			if aud == "complytime-gateway" {
				audFound = true
				break
			}
		}
		if !audFound {
			http.Error(w, "Unauthorized: invalid audience", http.StatusUnauthorized)
			return
		}

		issuer, ok := token.Issuer()
		if !ok || issuer == "" {
			http.Error(w, "Unauthorized: missing issuer", http.StatusUnauthorized)
			return
		}

		subject, ok := token.Subject()
		if !ok || subject == "" {
			http.Error(w, "Unauthorized: missing subject", http.StatusUnauthorized)
			return
		}

		ctx := authz.SetPublisherContext(r.Context(), issuer, subject)

		// Extract admin claim if present
		var isAdmin bool
		if err := token.Get("admin", &isAdmin); err == nil {
			ctx = authz.SetAdminContext(ctx, isAdmin)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func makeAuthenticatedRequest(t *testing.T, url, method, token string, body interface{}) *http.Response {
	t.Helper()

	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(method, url, bytes.NewReader(bodyJSON))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	return resp
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
