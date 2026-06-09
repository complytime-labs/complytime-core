// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/labstack/echo/v4"
)

type memoryUserStore struct {
	mu      sync.RWMutex
	users   map[string]*User
	changes []RoleChange
}

func newMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{users: make(map[string]*User)}
}

func (m *memoryUserStore) UpsertUser(_ context.Context, sub, issuer, email, name, avatarURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.users[email]; ok {
		u.Sub = sub
		u.Issuer = issuer
		u.Name = name
		u.AvatarURL = avatarURL
		return nil
	}
	m.users[email] = &User{
		Sub: sub, Issuer: issuer,
		Email: email, Name: name, AvatarURL: avatarURL,
		Role: consts.RoleReviewer, CreatedAt: time.Now(),
	}
	return nil
}

func (m *memoryUserStore) GetUserBySub(_ context.Context, sub, issuer string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Sub == sub && u.Issuer == issuer {
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *memoryUserStore) GetUser(_ context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (m *memoryUserStore) ListUsers(_ context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []User
	for _, u := range m.users {
		out = append(out, *u)
	}
	return out, nil
}

func (m *memoryUserStore) SetRole(_ context.Context, email, role string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return "", ErrUserNotFound
	}
	old := u.Role
	u.Role = role
	return old, nil
}

func (m *memoryUserStore) CountUsers(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *memoryUserStore) CountAdmins(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, u := range m.users {
		if u.Role == consts.RoleAdmin {
			count++
		}
	}
	return count, nil
}

func (m *memoryUserStore) InsertRoleChange(_ context.Context, change RoleChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	change.ChangedAt = time.Now()
	m.changes = append(m.changes, change)
	return nil
}

func (m *memoryUserStore) ListRoleChanges(_ context.Context) ([]RoleChange, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.changes, nil
}

func (m *memoryUserStore) BootstrapAdmin(_ context.Context, email string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Role == "admin" {
			return "", ErrAdminExists
		}
	}
	u, ok := m.users[email]
	if !ok {
		return "", ErrUserNotFound
	}
	old := u.Role
	u.Role = "admin"
	return old, nil
}

func testHandlerWithStore(t *testing.T) (*Handler, *memoryUserStore) {
	t.Helper()
	us := newMemoryUserStore()
	h := NewHandler()
	h.SetUserStore(us)
	return h, us
}

func TestMiddleware_ProxyHeaders(t *testing.T) {
	h, _ := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		sess, ok := SessionFrom(c.Request().Context())
		if !ok {
			return c.String(http.StatusUnauthorized, "no session")
		}
		return c.JSON(http.StatusOK, map[string]string{"email": sess.Email, "name": sess.Name})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
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
	h, _ := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_SkipsNonAPI(t *testing.T) {
	h, _ := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (non-API path should pass)", rec.Code)
	}
}

func TestMiddleware_SkipsAPIConfig(t *testing.T) {
	h, _ := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/config", func(c echo.Context) error {
		return c.String(http.StatusOK, "config")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (/api/config should pass without auth)", rec.Code)
	}
}

func TestMiddleware_NoStaticToken(t *testing.T) {
	h := NewHandler()
	us := newMemoryUserStore()
	h.SetUserStore(us)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bearer tokens no longer accepted by gateway)", rec.Code)
	}
}

func TestMiddleware_UpsertUserOnFirstSeen(t *testing.T) {
	h, us := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Forwarded-Email", "new@example.com")
	req.Header.Set("X-Forwarded-User", "sub-new")
	req.Header.Set("X-Forwarded-Preferred-Username", "New User")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	u, err := us.GetUser(context.TODO(), "new@example.com")
	if err != nil {
		t.Fatalf("user not upserted: %v", err)
	}
	if u.Role != consts.RoleReviewer {
		t.Fatalf("role = %q, want reviewer (default)", u.Role)
	}
}

func TestMiddleware_RoleSeedFromGroups(t *testing.T) {
	h, us := testHandlerWithStore(t)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Forwarded-Email", "first-admin@example.com")
	req.Header.Set("X-Forwarded-User", "sub-admin")
	req.Header.Set("X-Forwarded-Groups", "engineering,admins")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	u, err := us.GetUser(context.TODO(), "first-admin@example.com")
	if err != nil {
		t.Fatalf("user not found: %v", err)
	}
	if u.Role != consts.RoleAdmin {
		t.Fatalf("role = %q, want admin (seeded from groups)", u.Role)
	}
	changes, _ := us.ListRoleChanges(context.TODO())
	if len(changes) != 1 {
		t.Fatalf("role changes = %d, want 1", len(changes))
	}
}

func TestMiddleware_RoleSeedSkipsIfAdminExists(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-existing", "oauth2-proxy", "existing-admin@example.com", "Admin", "")
	_, _ = us.SetRole(context.TODO(), "existing-admin@example.com", consts.RoleAdmin)

	e := echo.New()
	e.Use(h.Middleware())
	e.GET("/api/test", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Forwarded-Email", "second@example.com")
	req.Header.Set("X-Forwarded-User", "sub-second")
	req.Header.Set("X-Forwarded-Groups", "admins")
	e.ServeHTTP(rec, req)

	u, _ := us.GetUser(context.TODO(), "second@example.com")
	if u.Role != consts.RoleReviewer {
		t.Fatalf("role = %q, want reviewer (admin already exists, no seed)", u.Role)
	}
}

func TestTokenFromRequest_XForwardedAccessToken(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/a2a/agent", nil)
	req.Header.Set("X-Forwarded-Access-Token", "ya29.access-token-123")

	token, ok := h.TokenFromRequest(req)
	if !ok || token != "ya29.access-token-123" { //nolint:gosec // G101: test fixture, not a real credential
		t.Fatalf("TokenFromRequest = (%q, %v), want (ya29.access-token-123, true)", token, ok)
	}
}

func TestTokenFromRequest_NoHeader(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/a2a/agent", nil)

	_, ok := h.TokenFromRequest(req)
	if ok {
		t.Fatal("expected false when no X-Forwarded-Access-Token header")
	}
}

func TestRequireWrite_WithUserStore(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-admin", "oauth2-proxy", "admin@co.com", "Admin", "")
	_, _ = us.SetRole(context.TODO(), "admin@co.com", consts.RoleAdmin)
	_ = us.UpsertUser(context.TODO(), "sub-viewer", "oauth2-proxy", "viewer@co.com", "Viewer", "")
	_ = us.UpsertUser(context.TODO(), "sub-writer", "oauth2-proxy", "writer@co.com", "Writer", "")
	_, _ = us.SetRole(context.TODO(), "writer@co.com", consts.RoleWriter)

	guard := RequireWrite(us)

	t.Run("admin passes", func(t *testing.T) {
		e := echo.New()
		e.Use(h.Middleware())
		e.Use(guard)
		e.Any("/*", func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/import", nil)
		req.Header.Set("X-Forwarded-Email", "admin@co.com")
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("reviewer blocked", func(t *testing.T) {
		e := echo.New()
		e.Use(h.Middleware())
		e.Use(guard)
		e.Any("/*", func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/import", nil)
		req.Header.Set("X-Forwarded-Email", "viewer@co.com")
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("writer passes import", func(t *testing.T) {
		e := echo.New()
		e.Use(h.Middleware())
		e.Use(guard)
		e.Any("/*", func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/policies/import", nil)
		req.Header.Set("X-Forwarded-Email", "writer@co.com")
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("writer blocked on users", func(t *testing.T) {
		e := echo.New()
		e.Use(h.Middleware())
		e.Use(guard)
		e.Any("/*", func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/api/users/someone@co.com/role", nil)
		req.Header.Set("X-Forwarded-Email", "writer@co.com")
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}

func TestHandleMe_WithUserStore(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-test", "oauth2-proxy", "test@co.com", "Test", "")
	_, _ = us.SetRole(context.TODO(), "test@co.com", consts.RoleAdmin)

	e := echo.New()
	e.Use(h.Middleware())
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
	if info.Role != consts.RoleAdmin {
		t.Fatalf("role = %q, want admin (from user store)", info.Role)
	}
}

func TestHandleSetRole(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-admin", "oauth2-proxy", "admin@co.com", "Admin", "")
	_, _ = us.SetRole(context.TODO(), "admin@co.com", consts.RoleAdmin)
	_ = us.UpsertUser(context.TODO(), "sub-target", "oauth2-proxy", "target@co.com", "Target", "")

	e := echo.New()
	e.Use(h.Middleware())
	h.RegisterUserAPI(e.Group("/api"))

	body := strings.NewReader(`{"role":"` + consts.RoleAdmin + `"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/users/target@co.com/role", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Email", "admin@co.com")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	u, _ := us.GetUser(context.TODO(), "target@co.com")
	if u.Role != consts.RoleAdmin {
		t.Fatalf("role = %q, want admin", u.Role)
	}

	changes, _ := us.ListRoleChanges(context.TODO())
	found := false
	for _, c := range changes {
		if c.TargetEmail == "target@co.com" && c.OldRole == consts.RoleReviewer && c.NewRole == consts.RoleAdmin {
			found = true
		}
	}
	if !found {
		t.Fatal("expected role change audit entry for target@co.com")
	}
}

func TestHandleSetRole_InvalidRole(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-admin", "oauth2-proxy", "admin@co.com", "Admin", "")
	_, _ = us.SetRole(context.TODO(), "admin@co.com", consts.RoleAdmin)

	e := echo.New()
	e.Use(h.Middleware())
	h.RegisterUserAPI(e.Group("/api"))

	body := strings.NewReader(`{"role":"superadmin"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/users/someone@co.com/role", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Email", "admin@co.com")
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleListUsers_AdminRequired(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-admin", "oauth2-proxy", "admin@co.com", "Admin", "")
	_, _ = us.SetRole(context.TODO(), "admin@co.com", consts.RoleAdmin)
	_ = us.UpsertUser(context.TODO(), "sub-viewer", "oauth2-proxy", "viewer@co.com", "Viewer", "")

	e := echo.New()
	e.Use(h.Middleware())
	h.RegisterUserAPI(e.Group("/api"))

	t.Run("admin can list", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("X-Forwarded-Email", "admin@co.com")
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var users []User
		_ = json.NewDecoder(rec.Body).Decode(&users)
		if len(users) != 2 {
			t.Fatalf("users = %d, want 2", len(users))
		}
	})

	t.Run("reviewer blocked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("X-Forwarded-Email", "viewer@co.com")
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("unauthenticated blocked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
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

func TestBootstrapAdmin_RaceProtection(t *testing.T) {
	h, us := testHandlerWithStore(t)
	_ = us.UpsertUser(context.TODO(), "sub-a", "oauth2-proxy", "a@co.com", "A", "")
	_ = us.UpsertUser(context.TODO(), "sub-b", "oauth2-proxy", "b@co.com", "B", "")

	e := echo.New()
	e.Use(h.Middleware())
	h.RegisterUserAPI(e.Group("/api"))

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/bootstrap", nil)
	req1.Header.Set("X-Forwarded-Email", "a@co.com")
	e.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first bootstrap status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/bootstrap", nil)
	req2.Header.Set("X-Forwarded-Email", "b@co.com")
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Fatalf("second bootstrap status = %d, want 409", rec2.Code)
	}
}
