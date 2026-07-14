package locker

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSharedSecretMiddleware(t *testing.T) {
	secret := "test-secret-value"
	handler := SharedSecretMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("rejects missing auth header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ledgers", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("rejects wrong secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ledgers", nil)
		req.Header.Set("Authorization", "Bearer wrong-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("accepts correct secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ledgers", nil)
		req.Header.Set("Authorization", "Bearer test-secret-value")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
