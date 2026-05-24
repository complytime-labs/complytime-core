# Authorization Implementation Design

**Date:** 2026-05-19  
**Status:** Approved  
**Related ADR:** ADR-0042 (Open Platform with Publisher-Gated Submission)

## Overview

Implement the three-layer authorization model defined in ADR-0042:
- **Layer 1:** Authenticated read access (OAuth2 Proxy validates OIDC token)
- **Layer 2:** Trusted publisher write access (JWT verification gates evidence submission)
- **Layer 3:** Trust signals (certification pipeline scores quality, not access control)

This design adds JWT-based publisher verification middleware, a database-backed trusted publisher registry with admin API, and enforces the "everyone can read, only trusted machines can write" model.

## Architecture

### Component Structure

**1. RequireJWT Middleware** (`internal/auth/publisher_middleware.go`)
- Extracts `Authorization: Bearer <jwt>` header from request
- Calls existing `JWTVerifier.Verify()` to validate signature, issuer, expiration
- Queries `PublisherStore` to check if `(iss, sub)` is trusted
- Returns `403 Forbidden` if verification fails or publisher not trusted
- Enriches request context with `PublisherIdentity` on success

**2. Publisher Store** (`internal/auth/publisher_store.go`)
- PostgreSQL-backed registry of trusted publishers
- Replaces static YAML config with runtime-managed database table
- Supports seeding from `PUBLISHER_CONFIG_PATH` on startup (idempotent upsert)
- Query methods: `IsTrusted(issuer, sub)`, `ListPublishers()`, `AddPublisher()`, `DeletePublisher()`

**3. Admin API** (`internal/auth/publisher_handlers.go`)
- `POST /api/admin/publishers` — add trusted publisher (requires `complytime-admin`)
- `GET /api/admin/publishers` — list all publishers (requires `complytime-admin`)
- `DELETE /api/admin/publishers/:id` — remove publisher (requires `complytime-admin`)
- Audit trail: `added_by` and `added_at` columns track who registered each publisher

**4. Updated Ingest Handler** (`internal/store/handlers_ingest.go`)
- Route wiring: apply `RequireJWT` middleware to `POST /api/ingest` only
- Simplified `resolvePublisherIdentity()`: reads `PublisherIdentity` from context (no fallback)
- Evidence insertion: `submitted_by`, `publisher_issuer`, `publisher_type`, `publisher_verified=true`

### Middleware Chain

```
POST /api/ingest
  ↓
OAuth2 Proxy (external) — validates OIDC session, injects X-Forwarded-Email
  ↓
auth.Middleware() — reads headers, injects Session into context
  ↓
auth.RequireJWT() — validates JWT, queries trusted_publishers, injects PublisherIdentity
  ↓
IngestAsyncHandler — reads PublisherIdentity from context, publishes to NATS
```

Read operations (`GET /api/policies`, `GET /api/evidence`) skip `RequireJWT` and only require OAuth2 Proxy authentication.

Admin operations (`DELETE /api/evidence/:id`) continue using existing `RequireWrite` middleware (checks `complytime-admin` role).

## Database Schema

### Trusted Publishers Table

```sql
CREATE TABLE trusted_publishers (
  publisher_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sub TEXT NOT NULL,
  allowed_types TEXT[], -- NULL = all types allowed, array for scoping
  added_by TEXT NOT NULL,
  added_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (issuer, sub)
);

CREATE INDEX idx_trusted_publishers_issuer ON trusted_publishers(issuer);
```

**Column Details:**
- `name` — human-readable label (e.g., "GitHub Actions Scanner", "Kyverno Policy Engine")
- `issuer` — JWT `iss` claim (e.g., `https://token.actions.githubusercontent.com`)
- `sub` — JWT `sub` claim (e.g., `repo:acme/scanner:ref:refs/heads/main`)
- `allowed_types` — optional scoping; if non-NULL, publisher can only submit specific artifact types
- `added_by` — email of admin who registered the publisher (audit trail)
- `added_at` — timestamp (audit trail)

**Constraints:**
- `UNIQUE (issuer, sub)` prevents duplicate registrations
- No soft deletes; publishers are immutable once added (delete and re-add if config changes)

### Migration Path

Migration `019_trusted_publishers.sql`:
1. Create `trusted_publishers` table
2. Seed from `PUBLISHER_CONFIG_PATH` if file exists (INSERT ON CONFLICT DO NOTHING)
3. No changes to `evidence` table (ADR-0035 already added publisher columns)

## API Specification

### Admin Endpoints

**POST /api/admin/publishers**

Create a new trusted publisher. Requires `complytime-admin` role.

Request:
```json
{
  "name": "GitHub Actions Scanner",
  "issuer": "https://token.actions.githubusercontent.com",
  "sub": "repo:acme/scanner:ref:refs/heads/main",
  "allowed_types": null
}
```

Response: `201 Created`
```json
{
  "publisher_id": "uuid",
  "name": "GitHub Actions Scanner",
  "issuer": "https://token.actions.githubusercontent.com",
  "sub": "repo:acme/scanner:ref:refs/heads/main",
  "allowed_types": null,
  "added_by": "admin@example.com",
  "added_at": "2026-05-19T12:00:00Z"
}
```

Errors:
- `403 Forbidden` — caller lacks `complytime-admin` role
- `409 Conflict` — `(issuer, sub)` already exists
- `400 Bad Request` — invalid issuer URL or empty sub

---

**GET /api/admin/publishers**

List all trusted publishers. Requires `complytime-admin` role.

Response: `200 OK`
```json
{
  "publishers": [
    {
      "publisher_id": "uuid",
      "name": "GitHub Actions Scanner",
      "issuer": "https://token.actions.githubusercontent.com",
      "sub": "repo:acme/scanner:ref:refs/heads/main",
      "allowed_types": null,
      "added_by": "admin@example.com",
      "added_at": "2026-05-19T12:00:00Z"
    }
  ]
}
```

Errors:
- `403 Forbidden` — caller lacks `complytime-admin` role

---

**DELETE /api/admin/publishers/:id**

Delete a trusted publisher. Requires `complytime-admin` role.

Response: `204 No Content`

Errors:
- `403 Forbidden` — caller lacks `complytime-admin` role
- `404 Not Found` — publisher ID does not exist

**Note:** Deleting a publisher does NOT invalidate existing evidence submitted by that publisher. Evidence rows retain their `publisher_issuer` and `publisher_verified=true` fields as historical record.

## Implementation Details

### PublisherStore Interface

```go
type PublisherStore interface {
    IsTrusted(ctx context.Context, issuer, sub string) (bool, error)
    ListPublishers(ctx context.Context) ([]TrustedPublisher, error)
    AddPublisher(ctx context.Context, p TrustedPublisher) error
    DeletePublisher(ctx context.Context, id string) error
    SeedFromConfig(ctx context.Context, publishers []TrustedPublisher) error
}

type TrustedPublisher struct {
    PublisherID  string
    Name         string
    Issuer       string
    Sub          string
    AllowedTypes []string
    AddedBy      string
    AddedAt      time.Time
}
```

### RequireJWT Middleware Pseudocode

```go
func RequireJWT(verifier *JWTVerifier, store PublisherStore) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // 1. Extract Bearer token
            token := extractBearerToken(c.Request())
            if token == "" {
                return c.JSON(403, map[string]string{
                    "error": "trusted publisher JWT required"
                })
            }
            
            // 2. Verify JWT signature + claims
            claims, err := verifier.Verify(c.Request().Context(), token)
            if err != nil {
                return c.JSON(403, map[string]string{
                    "error": "JWT verification failed",
                })
            }
            
            // 3. Check if publisher is trusted
            trusted, err := store.IsTrusted(c.Request().Context(), claims.Iss, claims.Sub)
            if err != nil {
                return c.JSON(500, map[string]string{
                    "error": "publisher verification failed"
                })
            }
            if !trusted {
                return c.JSON(403, map[string]string{
                    "error": "publisher not trusted",
                    "issuer": claims.Iss,
                    "subject": claims.Sub,
                })
            }
            
            // 4. Inject identity into context
            identity := &PublisherIdentity{
                Sub:      claims.Sub,
                Issuer:   claims.Iss,
                Type:     inferTypeFromClaims(claims),
                Verified: true,
            }
            ctx := context.WithValue(c.Request().Context(), publisherIdentityKey, identity)
            c.SetRequest(c.Request().WithContext(ctx))
            
            return next(c)
        }
    }
}
```

### Route Wiring

```go
func registerIngestRoutes(g *echo.Group, s Stores) {
    jwtMiddleware := auth.RequireJWT(s.JWTVerifier, s.Publishers)
    
    g.POST("/ingest", 
        echo.WrapHandler(IngestAsyncHandler(s.IngestPublisher, s.IngestTracker, s.JWTVerifier)), 
        jwtMiddleware,
    )
    
    g.GET("/ingest/jobs/:job_id", IngestJobStatusHandler(s.IngestTracker))
}
```

### Simplified resolvePublisherIdentity

```go
func resolvePublisherIdentity(r *http.Request) events.PublisherIdentity {
    identity, ok := auth.PublisherIdentityFrom(r.Context())
    if !ok {
        // This should never happen — middleware guarantees identity exists
        panic("RequireJWT middleware not applied to route")
    }
    return events.PublisherIdentity{
        SubmittedBy: identity.Sub,
        Issuer:      identity.Issuer,
        Type:        identity.Type,
        Verified:    true,
    }
}
```

Remove all fallback logic from this function — middleware enforces JWT requirement.

## Configuration

### Environment Variables

No new environment variables required. Existing:
- `PUBLISHER_CONFIG_PATH` — optional YAML file for seeding trusted publishers on startup
- `NATS_URL` — event bus for async ingest (already required)

### Publisher Config YAML (Optional Seed)

```yaml
publishers:
  - name: Kyverno Policy Engine
    issuer: https://kubernetes.default.svc.cluster.local
    sub: system:serviceaccount:kyverno:kyverno
    allowed_types: null
  - name: GitHub Actions Scanner
    issuer: https://token.actions.githubusercontent.com
    sub: repo:acme/scanner:ref:refs/heads/main
    allowed_types: ["control-catalog", "evaluation-log"]
```

On startup, Core reads this file and calls `PublisherStore.SeedFromConfig()` which performs `INSERT ... ON CONFLICT (issuer, sub) DO NOTHING`. Idempotent; safe to run on every restart.

Production deployments can ship base publishers in Helm chart, then GRC team adds more via admin API without redeploying.

## Error Handling

### JWT Verification Failures

**Missing Authorization header:**
- Status: `403 Forbidden`
- Body: `{"error": "trusted publisher JWT required"}`

**Invalid JWT (bad signature, expired, wrong audience):**
- Status: `403 Forbidden`
- Body: `{"error": "JWT verification failed"}`
- Logged: verification error details (not exposed to client to avoid token leak)

**Valid JWT from untrusted publisher:**
- Status: `403 Forbidden`
- Body: `{"error": "publisher not trusted", "issuer": "...", "subject": "..."}`
- GRC team can see issuer+sub in response to guide publisher registration

### Database Errors

**PublisherStore.IsTrusted() query failure:**
- Status: `500 Internal Server Error`
- Body: `{"error": "publisher verification failed"}`
- Logged: SQL error
- Fail closed (deny access on error, don't fall back to unverified)

**Admin API failures (409 Conflict on duplicate, 404 Not Found):**
- Standard HTTP semantics
- Client can retry with corrected input

## Testing Strategy

### Unit Tests

**`internal/auth/publisher_middleware_test.go`:**
- Missing Authorization header → 403
- Invalid JWT → 403
- Valid JWT from untrusted publisher → 403
- Valid JWT from trusted publisher → identity injected into context
- Database error during IsTrusted() → 500

**`internal/auth/publisher_store_test.go`:**
- IsTrusted() returns true for registered publisher
- IsTrusted() returns false for unregistered publisher
- AddPublisher() inserts row
- AddPublisher() returns error on duplicate `(issuer, sub)`
- DeletePublisher() removes row
- SeedFromConfig() is idempotent (run twice, only one row inserted)

### Integration Tests

**`internal/integration/auth_flow_test.go`:**
- End-to-end: register publisher via admin API → submit evidence with JWT → evidence inserted with `publisher_verified=true`
- Attempt submission without JWT → 403
- Attempt submission with JWT from untrusted publisher → 403
- Delete publisher → subsequent submissions rejected

## Migration & Rollout

### Phase 1: Database Migration
- Deploy migration `019_trusted_publishers.sql`
- Seed from `PUBLISHER_CONFIG_PATH` if file exists (Kyverno, central scanners)
- No breaking changes yet (fallback logic still active)

### Phase 2: Code Deployment
- Deploy new `RequireJWT` middleware
- Wire middleware to `POST /api/ingest` route
- Remove fallback logic from `resolvePublisherIdentity`
- **Breaking change:** Evidence submission now requires JWT

### Phase 3: Publisher Registration
- GRC team uses admin API to register team-specific publishers
- Teams test evidence submission with their registered publishers
- Monitor `403 Forbidden` errors for misconfigured publishers

### Rollback Plan
- If JWT enforcement causes issues, temporarily disable `RequireJWT` middleware (comment out route wiring)
- Evidence submission falls back to OAuth2 Proxy headers only
- Fix publisher configuration, re-enable middleware

## Security Considerations

### JWT Signature Verification
- JWTVerifier fetches JWKS from issuer's `/.well-known/openid-configuration`
- Keys cached with 1-hour TTL (mitigates JWKS endpoint outage)
- Invalid signature → hard reject (no fallback)

### Publisher Registry as Trust Boundary
- Only `complytime-admin` can add/remove publishers
- GRC team controls trust decisions (which publishers are allowed)
- Audit trail: `added_by` tracks who registered each publisher

### Evidence Integrity
- Publisher identity immutably recorded on evidence row
- Deleting a publisher does NOT invalidate existing evidence
- Certification pipeline (Layer 3) re-verifies evidence quality independently

### Defense Against Compromised Publisher
- If publisher JWT is compromised, attacker can submit fake evidence
- Mitigated by:
  - Certification pipeline flags low-quality evidence (VerdictFail)
  - GRC team can delete compromised publisher from registry
  - Evidence audit trail shows `submitted_by` for investigation

## Future Enhancements

### Artifact Type Scoping
- Implement `allowed_types` enforcement in `RequireJWT` middleware
- Check evidence artifact type against publisher's `allowed_types` array
- Reject submission if type not allowed

### Publisher Expiration
- Add `expires_at` column to `trusted_publishers` table
- Middleware checks expiration before accepting JWT
- Support time-bounded publisher access (e.g., 90-day contractor access)

### Publisher Request Workflow
- Add `POST /api/publisher-requests` (authenticated users can self-request)
- GRC team approves/rejects via `POST /api/admin/publisher-requests/:id/approve`
- Similar to Gemara-Hub ADR-0022 waitlist model
- Only implement if publisher registration volume becomes bottleneck

## Files to Create/Modify

### New Files
- `internal/auth/publisher_middleware.go` — RequireJWT middleware
- `internal/auth/publisher_store.go` — PostgreSQL-backed PublisherStore
- `internal/auth/publisher_handlers.go` — admin API handlers
- `internal/auth/publisher_middleware_test.go` — middleware unit tests
- `internal/auth/publisher_store_test.go` — store unit tests
- `internal/postgres/migrations/019_trusted_publishers.sql` — schema migration
- `internal/integration/publisher_flow_test.go` — end-to-end tests

### Modified Files
- `internal/store/handlers_ingest.go` — wire RequireJWT middleware, simplify resolvePublisherIdentity
- `internal/store/store.go` — add Publishers field to Stores struct
- `cmd/gateway/main.go` — initialize PublisherStore, seed from config
- `internal/auth/user_handlers.go` — register admin publisher routes

## Success Criteria

1. **JWT enforcement active:** `POST /api/ingest` returns `403 Forbidden` if JWT missing or invalid
2. **Admin API functional:** GRC team can add/list/delete publishers via `/api/admin/publishers`
3. **Evidence verified:** All new evidence has `publisher_verified=true` (no unverified evidence after deployment)
4. **Zero downtime:** Migration and deployment complete without service disruption
5. **Audit trail:** `trusted_publishers` table shows who added each publisher and when
