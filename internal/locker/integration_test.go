//go:build integration

package locker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	"github.com/complytime-labs/complytime-core/internal/ingest"
	"github.com/complytime-labs/complytime-core/internal/jobs"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

// TestLockerBasicOperations performs a basic lifecycle integration test:
// create ledger -> seal receipt -> fetch receipt -> verify receipt -> health check
func TestLockerBasicOperations(t *testing.T) {
	ctx := context.Background()

	// Create a locker with temporary storage
	lk, err := NewLocker(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { lk.Close(ctx) })

	// Create a handler with no auth (for integration test)
	handler := NewHandler(lk, nil, nil, nil, nil)

	const subjectID = "test-subject"
	testReceipt := []byte("test-receipt-data")

	// Step 1: Create ledger via internal API
	t.Run("create ledger", func(t *testing.T) {
		ledger, err := lk.CreateLedger(ctx, subjectID)
		require.NoError(t, err)
		assert.Equal(t, subjectID, ledger.SubjectID())
		assert.NotEmpty(t, ledger.VerifierKey())
	})

	// Step 2: Seal a receipt via internal API
	var sealedIndex uint64
	t.Run("seal receipt", func(t *testing.T) {
		ledger, ok := lk.GetLedger(subjectID)
		require.True(t, ok)
		idx, err := ledger.Seal(ctx, testReceipt)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, idx, uint64(0))
		sealedIndex = idx
	})

	// Step 3: Fetch the receipt
	t.Run("fetch receipt", func(t *testing.T) {
		url := fmt.Sprintf("/ledgers/%s/entry/%d", subjectID, int64(sealedIndex))
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		data, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Equal(t, testReceipt, data)
	})

	// Step 4: Verify receipt by digest
	var receiptDigest string
	t.Run("verify receipt", func(t *testing.T) {
		// Calculate digest
		receiptDigest = SHA256Hex(testReceipt)

		url := fmt.Sprintf("/ledgers/%s/verify/%s", subjectID, receiptDigest)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var verifyResp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&verifyResp)
		require.NoError(t, err)
		assert.True(t, verifyResp.Found)
		require.NotNil(t, verifyResp.Index)
		assert.Equal(t, sealedIndex, *verifyResp.Index)
	})

	// Step 5: Health check (list ledgers)
	t.Run("health check - list ledgers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ledgers", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var ledgerList LedgerList
		err := json.NewDecoder(w.Body).Decode(&ledgerList)
		require.NoError(t, err)
		assert.Len(t, ledgerList.Ledgers, 1)
		assert.Equal(t, subjectID, ledgerList.Ledgers[0].SubjectId)
	})

	// Step 6: Verify non-existent receipt fails appropriately
	t.Run("verify non-existent receipt", func(t *testing.T) {
		url := fmt.Sprintf("/ledgers/%s/verify/nonexistent", subjectID)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var verifyResp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&verifyResp)
		require.NoError(t, err)
		assert.False(t, verifyResp.Found)
	})
}

// TestLockerNATSConsumer tests the full locker NATS consumer flow:
// 1. Create locker with temp dir
// 2. Start embedded NATS server
// 3. Register a subject via the locker's RegisterSubject endpoint
// 4. Publish an IngestRef to JetStream (simulating what the gateway does)
// 5. Wait for the locker worker to seal it
// 6. Verify job status changes to sealed in NATS KV
// 7. Verify the receipt is fetchable from the locker
func TestLockerNATSConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Create locker with temp dir
	lockerDir := t.TempDir()
	lk, err := NewLocker(lockerDir)
	require.NoError(t, err)
	defer lk.Close(ctx)

	// Start embedded NATS server
	ns, js := startEmbeddedNATS(t)
	defer ns.Shutdown()

	// Ensure NATS infrastructure
	err = natsinfra.EnsureInfrastructure(ctx, js)
	require.NoError(t, err)

	// Get NATS connection
	nc, err := natsinfra.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	// Create trust store
	trustStore, err := trust.NewTrustStore(js)
	require.NoError(t, err)

	// Create event publisher
	eventPublisher := eventspkg.NewEventPublisher(nc, "complytime-test")

	// Create job store
	jobStatusKV, err := js.KeyValue(ctx, natsinfra.JobStatusBucket)
	require.NoError(t, err)
	jobStore := jobs.NewStore(jobStatusKV)

	// Create locker handler
	handler := NewHandler(lk, nil, nil, trustStore, eventPublisher)
	lockerServer := httptest.NewServer(handler)
	defer lockerServer.Close()

	// Start locker worker
	worker := NewWorker(js, lk, eventPublisher, jobStore)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	go worker.Start(workerCtx)
	defer worker.Stop()

	// Wait for worker to start
	time.Sleep(100 * time.Millisecond)

	// Test flow begins

	// 1. Register subject via locker's RegisterSubject endpoint
	subjectID := "test-nats-consumer"
	issuer := "http://test-issuer"
	sub := "test-publisher"

	registerReq := SubjectRegistrationRequest{
		SubjectId: subjectID,
		TrustedPublishers: []TrustedPublisher{
			{Issuer: issuer, Sub: sub},
		},
	}

	registerBody, err := json.Marshal(registerReq)
	require.NoError(t, err)

	registerResp, err := http.Post(lockerServer.URL+"/admin/subjects", "application/json", bytes.NewReader(registerBody))
	require.NoError(t, err)
	defer registerResp.Body.Close()
	require.Equal(t, http.StatusCreated, registerResp.StatusCode)

	var registerResult SubjectRegistrationResponse
	err = json.NewDecoder(registerResp.Body).Decode(&registerResult)
	require.NoError(t, err)
	assert.Equal(t, subjectID, registerResult.SubjectId)

	// 2. Create artifact and wrap as receipt (simulating gateway)
	artifact := map[string]interface{}{
		"type":      "test-artifact",
		"target":    map[string]string{"id": subjectID},
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      "locker nats consumer test",
	}
	artifactBytes, err := json.Marshal(artifact)
	require.NoError(t, err)

	publisher := receipt.Publisher{
		Issuer: issuer,
		Sub:    sub,
	}

	receiptBytes, err := receipt.Wrap(artifactBytes, publisher, subjectID, "test-artifact")
	require.NoError(t, err)

	// Calculate content digest
	contentDigest := SHA256Hex(artifactBytes)

	// 3. Create IngestRef and publish to JetStream
	jobID := "test-job-123"
	ingestRef := ingest.IngestRef{
		JobID:         jobID,
		SubjectID:     subjectID,
		ContentDigest: contentDigest,
		ArtifactType:  "test-artifact",
		ReceiptBytes:  receiptBytes,
	}

	refBytes, err := json.Marshal(ingestRef)
	require.NoError(t, err)

	_, err = js.Publish(ctx, natsinfra.SubjectIngest, refBytes)
	require.NoError(t, err)

	// 4. Set job as pending in NATS KV (simulating what gateway does)
	err = jobStore.SetPending(ctx, jobID, subjectID)
	require.NoError(t, err)

	// 5. Wait for job status to change to sealed
	var finalStatus *jobs.JobStatus
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := jobStore.Get(ctx, jobID)
		require.NoError(t, err)

		if status != nil && status.Status == jobs.Sealed {
			finalStatus = status
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	require.NotNil(t, finalStatus, "Job should be sealed")
	assert.Equal(t, jobs.Sealed, finalStatus.Status)
	require.NotNil(t, finalStatus.Digest, "Sealed job should have digest")
	require.NotNil(t, finalStatus.LogIndex, "Sealed job should have log index")

	// 6. Verify receipt is fetchable from locker
	receiptDigest := *finalStatus.Digest
	logIndex := *finalStatus.LogIndex

	// Fetch by index
	fetchURL := fmt.Sprintf("%s/ledgers/%s/entry/%d", lockerServer.URL, subjectID, logIndex)
	fetchResp, err := http.Get(fetchURL)
	require.NoError(t, err)
	defer fetchResp.Body.Close()
	require.Equal(t, http.StatusOK, fetchResp.StatusCode)

	fetchedReceipt, err := io.ReadAll(fetchResp.Body)
	require.NoError(t, err)
	assert.Equal(t, receiptBytes, fetchedReceipt)

	// Verify by digest
	verifyURL := fmt.Sprintf("%s/ledgers/%s/verify/%s", lockerServer.URL, subjectID, receiptDigest)
	verifyResp, err := http.Get(verifyURL)
	require.NoError(t, err)
	defer verifyResp.Body.Close()
	require.Equal(t, http.StatusOK, verifyResp.StatusCode)

	var verifyResult VerifyResponse
	err = json.NewDecoder(verifyResp.Body).Decode(&verifyResult)
	require.NoError(t, err)
	assert.True(t, verifyResult.Found)
	require.NotNil(t, verifyResult.Index)
	assert.Equal(t, logIndex, *verifyResult.Index)
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
