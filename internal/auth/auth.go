// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/labstack/echo/v4"
)

// Session represents the authenticated user identity injected into request
// context. Populated from X-Forwarded-* headers set by OAuth2 Proxy.
type Session struct {
	Login     string   `json:"l"`
	Name      string   `json:"n"`
	AvatarURL string   `json:"a"`
	Email     string   `json:"e"`
	Groups    []string `json:"g,omitempty"`
}

// UserInfo is the public-facing user info returned by /auth/me.
type UserInfo struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Email     string `json:"email"`
}

type contextKey string

const sessionKey contextKey = "session"

// SessionFrom extracts the Session from request context.
func SessionFrom(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey).(*Session)
	return s, ok
}

// Handler provides auth middleware and identity endpoints. Identity
// is established by OAuth2 Proxy via X-Forwarded-* headers.
type Handler struct{}

// NewHandler creates an auth handler. OAuth2 Proxy handles OIDC externally;
// the handler only reads proxy-injected headers.
func NewHandler() *Handler {
	return &Handler{}
}

// Register mounts auth endpoints. Login, callback, and logout are handled by
// OAuth2 Proxy at /oauth2/*. The /auth/logged-out page is excluded from proxy
// auth (via --skip-auth-route) so it renders after session cookie is cleared.
func (h *Handler) Register(e *echo.Echo) {
	e.GET("/auth/me", h.handleMeEcho)
	e.GET("/auth/logged-out", handleLoggedOut)
}

func handleLoggedOut(c echo.Context) error {
	return c.HTML(http.StatusOK, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signed Out — ComplyTime Studio</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#f8f9fa;color:#1e293b}
@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}.card{background:#1e293b;border-color:#334155}a{color:#4db8d1}}
.card{text-align:center;padding:48px 40px;border-radius:12px;background:#fff;border:1px solid #e2e8f0;box-shadow:0 4px 24px rgba(0,0,0,0.06);max-width:380px}
.card h2{font-size:1.25rem;font-weight:600;margin-bottom:8px}
.card p{font-size:0.9rem;color:#64748b;margin-bottom:24px}
a{color:#3b8ea5;text-decoration:none;font-weight:600;padding:10px 24px;border-radius:6px;border:1px solid currentColor;display:inline-block;transition:background 0.15s,color 0.15s}
a:hover{background:#3b8ea5;color:#fff}
</style></head>
<body><div class="card"><h2>Signed out</h2><p>Your session has ended.</p><a href="/">Sign in</a></div></body></html>`)
}

// Middleware reads X-Forwarded-* headers from OAuth2 Proxy and injects a
// Session into the request context. Falls through to anonymous for non-API
// paths.
func (h *Handler) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			requiresAuth := strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/workbench/")
			if !requiresAuth || r.URL.Path == "/api/config" {
				return next(c)
			}

			email := r.Header.Get("X-Forwarded-Email")
			if email == "" {
				authRequestTotal.Add("anonymous", 1)
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			}

			name := r.Header.Get("X-Forwarded-Preferred-Username")
			if name == "" {
				name = emailLocalPart(email)
			}
			sess := &Session{
				Email:  email,
				Name:   name,
				Login:  r.Header.Get("X-Forwarded-User"),
				Groups: splitGroups(r.Header.Get("X-Forwarded-Groups")),
			}

			ctx := context.WithValue(r.Context(), sessionKey, sess)
			ctx = httputil.WithIdentity(ctx, email)
			c.SetRequest(r.WithContext(ctx))
			authRequestTotal.Add("authenticated", 1)
			return next(c)
		}
	}
}

// TokenFromRequest reads the access token from the X-Forwarded-Access-Token
// header injected by OAuth2 Proxy. Used by A2A proxy and publish modules.
func (h *Handler) TokenFromRequest(r *http.Request) (string, bool) {
	token := r.Header.Get("X-Forwarded-Access-Token")
	if token == "" {
		return "", false
	}
	return token, true
}

func (h *Handler) handleMeEcho(c echo.Context) error {
	r := c.Request()
	email := r.Header.Get("X-Forwarded-Email")
	if email == "" {
		sess, ok := SessionFrom(r.Context())
		if ok {
			email = sess.Email
		}
	}
	if email == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
	}
	name := r.Header.Get("X-Forwarded-Preferred-Username")
	if name == "" {
		name = emailLocalPart(email)
	}
	info := UserInfo{
		Login:     r.Header.Get("X-Forwarded-User"),
		Name:      name,
		Email:     email,
		AvatarURL: r.Header.Get("X-Forwarded-Avatar-URL"),
	}
	return c.JSON(http.StatusOK, info)
}

func emailLocalPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func splitGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, g := range strings.Split(raw, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}
