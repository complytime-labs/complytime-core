package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// setupTestWorker creates a fresh NATS server and JetStream instance for each test.
// Each test gets its own isolated NATS server to avoid message leakage between tests.
func setupTestWorker(t *testing.T) (*server.Server, natsgo.JetStreamContext, jetstream.JetStream, *natsgo.Conn) {
	ns, err := server.NewServer(&server.Options{
		JetStream: true,
		Port:      -1,
		StoreDir:  t.TempDir(), // Isolated storage per test
	})
	require.NoError(t, err)
	go ns.Start()
	t.Cleanup(func() { ns.Shutdown() })

	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}

	nc, err := natsgo.Connect(ns.ClientURL())
	require.NoError(t, err)
	t.Cleanup(func() { nc.Close() })

	// Old JetStream context for EventPublisher
	jsCtx, err := nc.JetStream()
	require.NoError(t, err)

	// New JetStream for worker
	js, err := jetstream.New(nc)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, natsinfra.EnsureInfrastructure(ctx, js))

	return ns, jsCtx, js, nc
}

// TestWorker_NonDSSEPath tests the worker processing a non-DSSE IngestRef.
func TestWorker_NonDSSEPath(t *testing.T) {
	_, _, js, nc := setupTestWorker(t)
	ctx := context.Background()

	// Mock locker server
	var sealCalls int
	locker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ledgers/test-subject/seal" && r.Method == http.MethodPost {
			sealCalls++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"index":  int64(42),
				"digest": "abc123",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(locker.Close)

	// Create event publisher (uses old JetStream API)
	// Note: EventPublisher expects nats.Conn, not jetstream.JetStream
	eventPublisher := NewEventPublisher(nc)

	// Create job tracker
	jobs := &sync.Map{}
	jobID := "job-123"
	jobs.Store(jobID, &JobInfo{
		Status:    Pending,
		SubjectID: "test-subject",
	})

	// Create worker
	worker := NewWorker(js, locker.URL, "test-secret", eventPublisher, jobs)

	// Start worker in background
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Start(workerCtx)
	}()

	// Wait for worker to be ready
	time.Sleep(100 * time.Millisecond)

	// Publish IngestRef
	ingestRef := IngestRef{
		JobID:        jobID,
		SubjectID:    "test-subject",
		IsDSSE:       false,
		ReceiptBytes: []byte(`{"test":"receipt"}`),
	}
	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify locker was called
	assert.Equal(t, 1, sealCalls)

	// Verify job status updated
	jobVal, ok := jobs.Load(jobID)
	require.True(t, ok)
	jobInfo := jobVal.(*JobInfo)
	assert.Equal(t, Sealed, jobInfo.Status)
	require.NotNil(t, jobInfo.Digest)
	assert.Equal(t, "abc123", *jobInfo.Digest)
	require.NotNil(t, jobInfo.LogIndex)
	assert.Equal(t, int64(42), *jobInfo.LogIndex)

	// Shutdown worker
	cancel()
	select {
	case err := <-workerDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shutdown in time")
	}
}

// TestWorker_DSSEPath tests the worker processing a DSSE IngestRef.
func TestWorker_DSSEPath(t *testing.T) {
	_, _, js, nc := setupTestWorker(t)
	ctx := context.Background()

	// Mock locker server
	var mu sync.Mutex
	sealCalls := 0
	verifyCalls := 0
	locker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// Verify digest endpoint (accept any hex digest)
		if r.Method == http.MethodGet && len(r.URL.Path) > 30 {
			verifyCalls++
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"found": false,
			})
			return
		}

		// Seal endpoint
		if r.URL.Path == "/ledgers/test-subject/seal" && r.Method == http.MethodPost {
			sealCalls++
			// First seal: DSSE at index 10, second seal: channel attestation at index 11
			index := int64(10)
			digest := "dsse-digest-123"
			if sealCalls == 2 {
				index = 11
				digest = "attestation-digest-456"
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"index":  index,
				"digest": digest,
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(locker.Close)

	// Create event publisher
	eventPublisher := NewEventPublisher(nc)

	// Create job tracker
	jobs := &sync.Map{}
	jobID := "job-456"
	jobs.Store(jobID, &JobInfo{
		Status:    Pending,
		SubjectID: "test-subject",
	})

	// Create worker
	worker := NewWorker(js, locker.URL, "test-secret", eventPublisher, jobs)

	// Start worker in background
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Start(workerCtx)
	}()

	// Wait for worker to be ready
	time.Sleep(100 * time.Millisecond)

	// Build placeholder channel attestation (index -1 will be replaced by worker)
	publisher := receipt.Publisher{
		Issuer: "https://token.example.com",
		Sub:    "user@example.com",
	}
	dsseBytes := []byte(`{"payloadType":"test"}`)
	placeholderAttestation, err := receipt.BuildChannelAttestation("placeholder-digest", -1, publisher, "test-subject", "application/vnd.in-toto+json")
	require.NoError(t, err)

	// Publish DSSE IngestRef with placeholder channel attestation
	ingestRef := IngestRef{
		JobID:                   jobID,
		SubjectID:               "test-subject",
		IsDSSE:                  true,
		DSSEBytes:               dsseBytes,
		ChannelAttestationBytes: placeholderAttestation,
	}
	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify locker calls
	mu.Lock()
	assert.Equal(t, 1, verifyCalls, "should check if DSSE already sealed")
	assert.Equal(t, 2, sealCalls, "should seal DSSE and channel attestation")
	mu.Unlock()

	// Verify job status updated
	jobVal, ok := jobs.Load(jobID)
	require.True(t, ok)
	jobInfo := jobVal.(*JobInfo)
	assert.Equal(t, Sealed, jobInfo.Status)

	// Shutdown worker
	cancel()
	select {
	case err := <-workerDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shutdown in time")
	}
}

// TestWorker_DSSEAlreadySealed tests idempotent retry when DSSE is already sealed.
func TestWorker_DSSEAlreadySealed(t *testing.T) {
	_, _, js, nc := setupTestWorker(t)
	ctx := context.Background()

	// Mock locker server
	var mu sync.Mutex
	sealCalls := 0
	verifyCalls := 0
	locker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// Verify digest endpoint - DSSE already exists at index 5 (accept any hex digest)
		if r.Method == http.MethodGet && len(r.URL.Path) > 30 {
			verifyCalls++
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"found": true,
				"index": int64(5),
			})
			return
		}

		// Seal endpoint - only for channel attestation
		if r.URL.Path == "/ledgers/test-subject/seal" && r.Method == http.MethodPost {
			sealCalls++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"index":  int64(6),
				"digest": "attestation-digest-789",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(locker.Close)

	// Create event publisher
	eventPublisher := NewEventPublisher(nc)

	// Create job tracker
	jobs := &sync.Map{}
	jobID := "job-789"
	jobs.Store(jobID, &JobInfo{
		Status:    Pending,
		SubjectID: "test-subject",
	})

	// Create worker
	worker := NewWorker(js, locker.URL, "test-secret", eventPublisher, jobs)

	// Start worker in background
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Start(workerCtx)
	}()

	// Wait for worker to be ready
	time.Sleep(100 * time.Millisecond)

	// Build placeholder channel attestation
	publisher := receipt.Publisher{
		Issuer: "https://token.example.com",
		Sub:    "user@example.com",
	}
	dsseBytes := []byte(`{"payloadType":"test"}`)
	placeholderAttestation, err := receipt.BuildChannelAttestation("placeholder-digest", -1, publisher, "test-subject", "application/vnd.in-toto+json")
	require.NoError(t, err)

	// Publish DSSE IngestRef
	ingestRef := IngestRef{
		JobID:                   jobID,
		SubjectID:               "test-subject",
		IsDSSE:                  true,
		DSSEBytes:               dsseBytes,
		ChannelAttestationBytes: placeholderAttestation,
	}
	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify locker calls
	mu.Lock()
	assert.Equal(t, 1, verifyCalls, "should check if DSSE already sealed")
	assert.Equal(t, 1, sealCalls, "should only seal channel attestation, not DSSE")
	mu.Unlock()

	// Verify job status updated
	jobVal, ok := jobs.Load(jobID)
	require.True(t, ok)
	jobInfo := jobVal.(*JobInfo)
	assert.Equal(t, Sealed, jobInfo.Status)

	// Shutdown worker
	cancel()
	select {
	case err := <-workerDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shutdown in time")
	}
}

// TestWorker_TransientFailureRetry tests that transient failures trigger NakWithDelay.
func TestWorker_TransientFailureRetry(t *testing.T) {
	_, _, js, nc := setupTestWorker(t)
	ctx := context.Background()

	// Mock locker server that fails then succeeds
	var mu sync.Mutex
	sealAttempts := 0
	locker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/ledgers/test-subject/seal" && r.Method == http.MethodPost {
			sealAttempts++
			// Fail first attempt (simulating network error or service unavailable)
			if sealAttempts == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			// Succeed on retry
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"index":  int64(1),
				"digest": "retry-digest",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(locker.Close)

	// Create event publisher
	eventPublisher := NewEventPublisher(nc)

	// Create job tracker
	jobs := &sync.Map{}
	jobID := "job-retry"
	jobs.Store(jobID, &JobInfo{
		Status:    Pending,
		SubjectID: "test-subject",
	})

	// Create worker
	worker := NewWorker(js, locker.URL, "test-secret", eventPublisher, jobs)

	// Start worker in background
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Start(workerCtx)
	}()

	// Wait for worker to be ready
	time.Sleep(100 * time.Millisecond)

	// Publish IngestRef
	ingestRef := IngestRef{
		JobID:        jobID,
		SubjectID:    "test-subject",
		IsDSSE:       false,
		ReceiptBytes: []byte(`{"test":"receipt"}`),
	}
	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// Wait for retry processing (initial attempt + retry after delay)
	time.Sleep(7 * time.Second)

	// Verify multiple attempts
	mu.Lock()
	assert.GreaterOrEqual(t, sealAttempts, 2, "should retry after transient failure")
	mu.Unlock()

	// Verify job eventually succeeded
	jobVal, ok := jobs.Load(jobID)
	require.True(t, ok)
	jobInfo := jobVal.(*JobInfo)
	assert.Equal(t, Sealed, jobInfo.Status)

	// Shutdown worker
	cancel()
	select {
	case err := <-workerDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shutdown in time")
	}
}

// TestWorker_PermanentFailureTerm tests that permanent failures terminate the message.
func TestWorker_PermanentFailureTerm(t *testing.T) {
	_, _, js, nc := setupTestWorker(t)
	ctx := context.Background()

	// Mock locker server that always returns 404 (ledger not found)
	var mu sync.Mutex
	sealAttempts := 0
	locker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.URL.Path == "/ledgers/nonexistent-subject/seal" && r.Method == http.MethodPost {
			sealAttempts++
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "ledger not found",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(locker.Close)

	// Create event publisher
	eventPublisher := NewEventPublisher(nc)

	// Create job tracker
	jobs := &sync.Map{}
	jobID := "job-fail"
	jobs.Store(jobID, &JobInfo{
		Status:    Pending,
		SubjectID: "nonexistent-subject",
	})

	// Create worker
	worker := NewWorker(js, locker.URL, "test-secret", eventPublisher, jobs)

	// Start worker in background
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Start(workerCtx)
	}()

	// Wait for worker to be ready
	time.Sleep(100 * time.Millisecond)

	// Publish IngestRef
	ingestRef := IngestRef{
		JobID:        jobID,
		SubjectID:    "nonexistent-subject",
		IsDSSE:       false,
		ReceiptBytes: []byte(`{"test":"receipt"}`),
	}
	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify only attempted once (permanent failure terminates)
	mu.Lock()
	assert.Equal(t, 1, sealAttempts, "should not retry permanent failure")
	mu.Unlock()

	// Verify job status is failed
	jobVal, ok := jobs.Load(jobID)
	require.True(t, ok)
	jobInfo := jobVal.(*JobInfo)
	assert.Equal(t, Failed, jobInfo.Status)

	// Shutdown worker
	cancel()
	select {
	case err := <-workerDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shutdown in time")
	}
}
