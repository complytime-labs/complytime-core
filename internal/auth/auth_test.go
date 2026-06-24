// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/labstack/echo/v4"
)

func newTestAuthorizer(t *testing.T) *authz.Authorizer {
	t.Helper()
	a, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create test authorizer: %v", err)
	}
	return a
}

func TestMiddleware_ProxyHeaders(t *testing.T) {
	h := NewHandler(newTestAuthorizer(t))

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/config", func(c echo.Context) error {
		sess, ok := SessionFrom(c.Request().Context())
		if !ok {
			return c.String(http.StatusUnauthorized, "no session")
		}
		return c.JSON(http.StatusOK, map[string]string{"email": sess.Email, "name": sess.Name})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	req.Header.Set("X-Forwarded-Preferred-Username", "alice")
	req.Header.Set("X-Forwarded-User", "auth0|abc123")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["email"] != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", body["email"])
	}
	if body["name"] != "alice" {
		t.Fatalf("name = %q, want alice", body["name"])
	}
}

func TestMiddleware_NoHeaders_Returns401(t *testing.T) {
	h := NewHandler(newTestAuthorizer(t))

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/config", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_SkipsHealthz(t *testing.T) {
	h := NewHandler(newTestAuthorizer(t))

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (/healthz should pass without auth)", rec.Code)
	}
}

func TestMiddleware_APIConfigWithAuth(t *testing.T) {
	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	h := NewHandler(authorizer)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/config", func(c echo.Context) error {
		return c.String(http.StatusOK, "config")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.Header.Set("X-Forwarded-Email", "user@example.com")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (/api/config with auth should be allowed)", rec.Code)
	}
}

func TestMiddleware_NoStaticToken(t *testing.T) {
	h := NewHandler(newTestAuthorizer(t))

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/config", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bearer tokens no longer accepted by gateway)", rec.Code)
	}
}

func TestTokenFromRequest_XForwardedAccessToken(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/a2a/agent", nil)
	req.Header.Set("X-Forwarded-Access-Token", "ya29.access-token-123")

	token, ok := h.TokenFromRequest(req)
	if !ok || token != "ya29.access-token-123" { //nolint:gosec // G101: test fixture, not a real credential
		t.Fatalf("TokenFromRequest = (%q, %v), want (ya29.access-token-123, true)", token, ok)
	}
}

func TestTokenFromRequest_NoHeader(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/a2a/agent", nil)

	_, ok := h.TokenFromRequest(req)
	if ok {
		t.Fatal("expected false when no X-Forwarded-Access-Token header")
	}
}

func TestHandleMe_ReturnsIdentity(t *testing.T) {
	h := NewHandler(nil)

	e := echo.New()
	h.Register(e)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("X-Forwarded-Email", "test@co.com")
	req.Header.Set("X-Forwarded-User", "sub-test")
	req.Header.Set("X-Forwarded-Preferred-Username", "Test")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var info UserInfo
	_ = json.NewDecoder(rec.Body).Decode(&info)
	if info.Email != "test@co.com" {
		t.Fatalf("email = %q, want test@co.com", info.Email)
	}
	if info.Name != "Test" {
		t.Fatalf("name = %q, want Test", info.Name)
	}
	if info.Login != "sub-test" {
		t.Fatalf("login = %q, want sub-test", info.Login)
	}
}

func TestSplitGroups(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"admins", 1},
		{"admins,engineering,dev", 3},
		{"admins, engineering , dev", 3},
	}
	for _, tt := range tests {
		got := splitGroups(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitGroups(%q) = %d groups, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestMiddleware_RequiresAuthForTlogPaths(t *testing.T) {
	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	h := NewHandler(authorizer)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/checkpoint", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	e.GET("/tile/entries/000", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	e.GET("/log/witnessed/0", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	tests := []struct {
		path string
	}{
		{"/checkpoint"},
		{"/tile/entries/000"},
		{"/log/witnessed/0"},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: status = %d, want 401", tt.path, rec.Code)
		}
	}
}

func TestMiddleware_TlogPathsWithAuth(t *testing.T) {
	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	h := NewHandler(authorizer)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/checkpoint", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})
	e.GET("/log/witnessed/0", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	tests := []struct {
		path string
	}{
		{"/checkpoint"},
		{"/log/witnessed/0"},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		req.Header.Set("X-Forwarded-Email", "user@example.com")
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s with auth: status = %d, want 200 (read:checkpoint is permitted for all)", tt.path, rec.Code)
		}
	}
}

func TestMiddleware_TlogEntriesDeniedWithoutGroup(t *testing.T) {
	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	h := NewHandler(authorizer)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/tile/entries/000", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tile/entries/000", nil)
	req.Header.Set("X-Forwarded-Email", "user@example.com")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (read:entries requires auditors group)", rec.Code)
	}
}

func TestMiddleware_TlogEntriesAllowedWithGroup(t *testing.T) {
	authorizer, err := authz.NewAuthorizer("")
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	h := NewHandler(authorizer)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/tile/entries/000", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tile/entries/000", nil)
	req.Header.Set("X-Forwarded-Email", "auditor@example.com")
	req.Header.Set("X-Forwarded-Groups", "auditors")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (read:entries allowed for auditors)", rec.Code)
	}
}
