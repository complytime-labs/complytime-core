# ADR-0002: Migrate Gateway to Echo Framework

**Status:** Accepted (migration complete)
**Date:** 2026-05-01

## Problem

The gateway used Go stdlib `net/http` with hand-rolled middleware for OIDC validation, RBAC, CORS, request logging, and JSON binding. Every cross-cutting concern was custom code.

## Decision

**Migrate from `net/http` to Echo (labstack/echo).** All API handlers converted to native Echo handlers.

## Alternatives Considered

| Framework | Verdict |
|:--|:--|
| Chi | Rejected — router only, doesn't solve the middleware problem |
| Gin | Rejected — similar to Echo but handler signatures diverge further from `net/http` |
| Fiber | Rejected — uses `fasthttp`, not `net/http`, all existing middleware breaks |
| **Echo** | **Accepted** — built-in CORS/rate-limiting/body-limit, clean middleware composition, wraps `net/http` |

## What Echo Provides

| Concern | Implementation |
|:--|:--|
| Panic recovery | `middleware.Recover()` |
| Request IDs | `middleware.RequestID()` |
| Security headers | `middleware.SecureWithConfig(...)` — CSP, X-Frame, Referrer |
| CORS | `middleware.CORSWithConfig(...)` |
| Body size limit | `middleware.BodyLimit(...)` on `/api` group |
| Request binding | `c.Bind(&v)` replaces `json.NewDecoder(io.LimitReader(...))` |
| JSON responses | `c.JSON(status, v)` replaces `httputil.WriteJSON(w, ...)` |
| Path params | `c.Param("id")` with `:id` route syntax |
| Auth | OAuth2 Proxy sidecar (OIDC handled externally); gateway reads `X-Forwarded-*` headers |
| Write protection | `writeProtect(auth.RequireAdmin(...))` middleware |

## Migration Scope

| Package | Status |
|:--|:--|
| `internal/store` | Native Echo — `Register(g *echo.Group, ...)`, includes posture + evidence handlers |
| `internal/postgres` | Data layer — no HTTP handlers (provides `Client` used by store) |
| `internal/auth` | Native Echo — `Middleware()`, `RegisterUserAPI(g)`, `RegisterChatHistory(g, cs)` |
| `cmd/ingest` | Native Echo — healthz, system-info, gemara proxy |
| `internal/registry` | Wrapped via `echo.WrapHandler(mux)` — stdlib handlers |
| `internal/publish` | Wrapped via `echo.WrapHandler(mux)` — stdlib handlers |
| `internal/agents` | Wrapped via `echo.WrapHandler(mux)` — stdlib handlers |
| `internal/config` | Wrapped via `echo.WrapHandler(mux)` — stdlib handlers |
| `internal/web` | Wrapped via `echo.WrapHandler(mux)` — SPA static assets |

Infrastructure packages (`registry`, `publish`, `agents`, `config`, `web`) remain stdlib and are wrapped via `echo.WrapHandler(mux)`. They still receive all Echo middleware. Conversion is deferred — no user-facing value.
