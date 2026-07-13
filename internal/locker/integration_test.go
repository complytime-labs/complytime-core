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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration performs a full lifecycle integration test:
// create ledger -> seal receipt -> fetch receipt -> verify receipt -> health check
func TestIntegration(t *testing.T) {
	ctx := context.Background()

	// Create a locker with temporary storage
	lk, err := NewLocker(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { lk.Close(ctx) })

	// Create a handler
	handler := NewHandler(lk, "")

	const subjectID = "test-subject"
	testReceipt := []byte("test-receipt-data")

	// Step 1: Create ledger
	t.Run("create ledger", func(t *testing.T) {
		reqBody := CreateLedgerRequest{SubjectId: subjectID}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/ledgers", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var ledgerInfo LedgerInfo
		err = json.NewDecoder(w.Body).Decode(&ledgerInfo)
		require.NoError(t, err)
		assert.Equal(t, subjectID, ledgerInfo.SubjectId)
		assert.NotEmpty(t, ledgerInfo.VerifierKey)
	})

	// Step 2: Seal a receipt
	var sealedIndex int64
	t.Run("seal receipt", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"/ledgers/"+subjectID+"/seal",
			bytes.NewReader(testReceipt),
		)
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var sealResp SealResponse
		err := json.NewDecoder(w.Body).Decode(&sealResp)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, sealResp.Index, int64(0))
		assert.NotEmpty(t, sealResp.Digest)
		sealedIndex = sealResp.Index
	})

	// Step 3: Fetch the receipt
	t.Run("fetch receipt", func(t *testing.T) {
		url := fmt.Sprintf("/ledgers/%s/entry/%d", subjectID, sealedIndex)
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
