package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authn"
)

func TestStaticTokenSource(t *testing.T) {
	src := authn.NewStaticTokenSource("my-token")
	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "my-token", tok)
}

func TestFileTokenSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("file-token-v1\n"), 0600))

	src := authn.NewFileTokenSource(path)
	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "file-token-v1", tok)

	// Update file, source should return new value
	require.NoError(t, os.WriteFile(path, []byte("file-token-v2\n"), 0600))
	tok, err = src.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "file-token-v2", tok)
}

func TestFileTokenSource_MissingFile(t *testing.T) {
	src := authn.NewFileTokenSource("/nonexistent/path/token")
	_, err := src.Token(context.Background())
	require.Error(t, err)
}

func TestTokenTransport(t *testing.T) {
	src := authn.NewStaticTokenSource("svc-token")
	transport := authn.NewTokenTransport(src, http.DefaultTransport)
	client := &http.Client{Transport: transport}

	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer svc-token", captured)
}
