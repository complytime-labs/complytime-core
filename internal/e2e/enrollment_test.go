// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/postgres"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E_TargetRegistrationFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	pgURL := os.Getenv("POSTGRES_TEST_URL")
	if pgURL == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping integration test")
	}

	ctx := context.Background()

	// Setup infrastructure
	pgClient, err := postgres.New(ctx, postgres.Config{URL: pgURL})
	require.NoError(t, err)
	defer pgClient.Close()

	err = pgClient.EnsureSchema(ctx)
	require.NoError(t, err)

	st := store.New(pgClient.Pool())
	natsServer := startTestNATSServer(t)
	natsURL := natsServer.ClientURL()
	tesseraClient := newTestTessera(t)
	jwtCtx := newTestJWTVerifier(t)
	bus := connectTestNATS(t, natsURL)
	tracker := store.NewIngestTracker()

	// Subscribe to target registration events before submitting
	eventCh := make(chan events.TargetRegisteredEvent, 1)
	eventBus := connectTestNATS(t, natsURL)
	_, err = eventBus.SubscribeTargetRegistered(func(evt events.TargetRegisteredEvent) {
		eventCh <- evt
	})
	require.NoError(t, err)

	// Start worker
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()

	stores := store.Stores{
		Evidence: st,
		Policies: st,
		Controls: st,
		Mappings: st,
		Targets:  st,
	}

	worker := store.IngestWorker(workerCtx, stores, bus, tracker)
	_, err = bus.SubscribeIngestRaw(worker)
	require.NoError(t, err)

	// Create HTTP server
	ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingestHandler.ServeHTTP(w, r)
	}))
	defer server.Close()

	// Load TargetRegistration fixture
	regYAML, err := os.ReadFile("testdata/target_registration_sample.yaml")
	require.NoError(t, err)

	// Generate JWT
	testSubject := "repo:org/infrastructure:ref:refs/heads/main"
	token := jwtCtx.generateTestJWT(t, testSubject)

	// Submit TargetRegistration
	resp, result := submitEvidence(t, server.URL, token, regYAML)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "Expected 202 Accepted")

	jobID := result["job_id"].(string)
	logIndex := uint64(result["log_index"].(float64))
	t.Logf("Submitted TargetRegistration: job_id=%s, log_index=%d", jobID, logIndex)

	// Wait for worker to process
	waitForJobCompletion(t, tracker, jobID, 10*time.Second)
	t.Logf("Worker completed job %s", jobID)

	// Verify Tessera contains entry
	tesseraEntry, err := tesseraClient.Read(ctx, logIndex)
	require.NoError(t, err)
	require.NotEmpty(t, tesseraEntry)
	require.Contains(t, string(tesseraEntry), "TargetRegistration")
	t.Logf("Verified: TargetRegistration in Tessera at log_index %d", logIndex)

	// Verify target stored in PostgreSQL with correct dimensions
	target, err := st.GetLatestTarget(ctx, "prod-cluster", time.Now())
	require.NoError(t, err)
	require.NotNil(t, target, "Target not found in database")

	assert.Equal(t, "prod-cluster", target.TargetID)
	assert.Equal(t, "Production Kubernetes Cluster", target.TargetName)
	assert.Equal(t, "kubernetes-cluster", target.TargetType)
	assert.Equal(t, []string{"kubernetes", "postgresql"}, target.Technologies)
	assert.Equal(t, []string{"EU"}, target.Geopolitical)
	assert.Equal(t, []string{"confidential"}, target.Sensitivity)
	assert.Equal(t, testSubject, target.RegisteredBy)
	assert.Equal(t, logIndex, target.TesseraLogIndex)
	t.Logf("Verified: Target in PostgreSQL with correct dimensions")

	// Verify NATS event received
	select {
	case evt := <-eventCh:
		assert.Equal(t, "prod-cluster", evt.TargetID)
		assert.Equal(t, logIndex, evt.LogIndex)
		assert.Equal(t, testSubject, evt.RegisteredBy)
		t.Logf("Verified: core.target.registered NATS event received")
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for core.target.registered NATS event")
	}

	t.Logf("TargetRegistration E2E test PASSED")
}

func TestE2E_PolicyDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	pgURL := os.Getenv("POSTGRES_TEST_URL")
	if pgURL == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping integration test")
	}

	ctx := context.Background()

	// Setup infrastructure
	pgClient, err := postgres.New(ctx, postgres.Config{URL: pgURL})
	require.NoError(t, err)
	defer pgClient.Close()

	err = pgClient.EnsureSchema(ctx)
	require.NoError(t, err)

	st := store.New(pgClient.Pool())
	natsServer := startTestNATSServer(t)
	tesseraClient := newTestTessera(t)
	jwtCtx := newTestJWTVerifier(t)
	bus := connectTestNATS(t, natsServer.ClientURL())
	tracker := store.NewIngestTracker()

	// Start worker
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()

	stores := store.Stores{
		Evidence:         st,
		Policies:         st,
		Controls:         st,
		Mappings:         st,
		Targets:          st,
		PolicyDimensions: st,
	}

	worker := store.IngestWorker(workerCtx, stores, bus, tracker)
	_, err = bus.SubscribeIngestRaw(worker)
	require.NoError(t, err)

	// Create ingest HTTP server
	ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
	ingestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingestHandler.ServeHTTP(w, r)
	}))
	defer ingestServer.Close()

	// Create API server with policy discovery endpoint
	apiServer := setupAPIServer(t, stores)
	defer apiServer.Close()

	// Step 1: Register target
	regYAML, err := os.ReadFile("testdata/target_registration_sample.yaml")
	require.NoError(t, err)

	token := jwtCtx.generateTestJWT(t, "repo:org/infrastructure:ref:refs/heads/main")
	resp, result := submitEvidence(t, ingestServer.URL, token, regYAML)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	waitForJobCompletion(t, tracker, result["job_id"].(string), 10*time.Second)
	t.Logf("Registered target prod-cluster")

	// Step 2: Insert policy with matching dimensions directly
	_, err = pgClient.Pool().Exec(ctx,
		`INSERT INTO policies (policy_id, title, version, technologies, geopolitical,
		 evaluation_timeline_start, evaluation_timeline_end, tessera_log_index)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (policy_id) DO UPDATE SET
		   technologies = EXCLUDED.technologies,
		   geopolitical = EXCLUDED.geopolitical,
		   evaluation_timeline_start = EXCLUDED.evaluation_timeline_start,
		   evaluation_timeline_end = EXCLUDED.evaluation_timeline_end,
		   tessera_log_index = EXCLUDED.tessera_log_index`,
		"infra-baseline", "Infrastructure Baseline", "2.0.0",
		[]string{"kubernetes"}, []string{"EU"},
		time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		int64(100),
	)
	require.NoError(t, err)
	t.Logf("Inserted policy with kubernetes+EU dimensions")

	// Step 3: Query for applicable policies
	queryURL := fmt.Sprintf("%s/api/policies/discover?target_id=prod-cluster&timestamp=2026-05-26T10:00:00Z", apiServer.URL)
	queryResp, err := http.Get(queryURL)
	require.NoError(t, err)
	defer func() { _ = queryResp.Body.Close() }()
	require.Equal(t, http.StatusOK, queryResp.StatusCode)

	var policyResp store.PolicyQueryResponse
	err = json.NewDecoder(queryResp.Body).Decode(&policyResp)
	require.NoError(t, err)

	// Verify target info
	assert.Equal(t, "prod-cluster", policyResp.Target.ID)
	assert.Equal(t, "Production Kubernetes Cluster", policyResp.Target.Name)

	// Verify matching policy found
	require.Len(t, policyResp.ApplicablePolicies, 1, "Expected 1 applicable policy")
	assert.Equal(t, "infra-baseline", policyResp.ApplicablePolicies[0].PolicyID)
	assert.Equal(t, uint64(100), policyResp.ApplicablePolicies[0].LogIndex)
	t.Logf("Verified: Policy infra-baseline matches prod-cluster dimensions")

	// Step 4: Query with non-existent target
	queryURL = fmt.Sprintf("%s/api/policies/discover?target_id=nonexistent&timestamp=2026-05-26T10:00:00Z", apiServer.URL)
	queryResp2, err := http.Get(queryURL)
	require.NoError(t, err)
	defer func() { _ = queryResp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, queryResp2.StatusCode)
	t.Logf("Verified: Non-existent target returns 404")

	t.Logf("Policy discovery E2E test PASSED")
}

func TestE2E_TargetRegistrationRejectsMissingTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	pgURL := os.Getenv("POSTGRES_TEST_URL")
	if pgURL == "" {
		t.Skip("POSTGRES_TEST_URL not set, skipping integration test")
	}

	ctx := context.Background()

	pgClient, err := postgres.New(ctx, postgres.Config{URL: pgURL})
	require.NoError(t, err)
	defer pgClient.Close()

	err = pgClient.EnsureSchema(ctx)
	require.NoError(t, err)

	st := store.New(pgClient.Pool())
	natsServer := startTestNATSServer(t)
	tesseraClient := newTestTessera(t)
	jwtCtx := newTestJWTVerifier(t)
	bus := connectTestNATS(t, natsServer.ClientURL())
	tracker := store.NewIngestTracker()

	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()

	stores := store.Stores{Evidence: st, Policies: st, Controls: st, Mappings: st, Targets: st}
	worker := store.IngestWorker(workerCtx, stores, bus, tracker)
	_, err = bus.SubscribeIngestRaw(worker)
	require.NoError(t, err)

	ingestHandler := store.IngestAsyncHandler(bus, tracker, tesseraClient, jwtCtx.Verifier)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingestHandler.ServeHTTP(w, r)
	}))
	defer server.Close()

	// Submit malformed TargetRegistration (missing target.id)
	malformedYAML := []byte(`metadata:
  type: TargetRegistration
  id: bad-reg
  date: "2026-05-26T10:00:00Z"
target:
  name: Missing ID Target
dimensions:
  technologies: [kubernetes]
`)

	token := jwtCtx.generateTestJWT(t, "repo:org/test:ref:refs/heads/main")
	resp, result := submitEvidence(t, server.URL, token, malformedYAML)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	jobID := result["job_id"].(string)

	// Wait for worker — job should fail
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status := tracker.Get(jobID)
		if status != nil && status.Status == "failed" {
			assert.Contains(t, status.Error, "missing target.id")
			t.Logf("Verified: Malformed TargetRegistration correctly rejected: %s", status.Error)
			return
		}
		if status != nil && status.Status == "completed" {
			t.Fatal("Expected job to fail, but it completed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Timed out waiting for job to fail")
}

// setupAPIServer creates an Echo server with the policy discovery routes
func setupAPIServer(t *testing.T, stores store.Stores) *httptest.Server {
	t.Helper()

	e := newTestEchoServer()
	apiGroup := e.Group("/api")
	store.Register(apiGroup, stores)

	return httptest.NewServer(e)
}
