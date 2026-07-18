package locker_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lockerdriver "github.com/complytime-labs/complytime-core/drivers/locker"
)

func TestDriver_Fetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ledgers/my-subject/entry/42", r.URL.Path)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("receipt-data"))
	}))
	defer server.Close()

	driver := lockerdriver.NewDriver(server.URL, &http.Client{})
	rc, err := driver.Fetch(context.Background(), "locker://my-subject/entry/42")
	require.NoError(t, err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "receipt-data", string(data))
}

func TestDriver_Fetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	driver := lockerdriver.NewDriver(server.URL, &http.Client{})
	_, err := driver.Fetch(context.Background(), "locker://my-subject/entry/999")
	require.Error(t, err)
}

func TestDriver_Fetch_InvalidURI(t *testing.T) {
	driver := lockerdriver.NewDriver("http://localhost", &http.Client{})
	_, err := driver.Fetch(context.Background(), "locker://no-entry-path")
	require.Error(t, err)
}
