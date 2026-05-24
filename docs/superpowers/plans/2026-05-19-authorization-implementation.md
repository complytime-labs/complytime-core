# Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement three-layer authorization model with JWT-based trusted publisher verification for evidence submission.

**Architecture:** Add RequireJWT middleware that validates JWT tokens against a PostgreSQL-backed trusted publisher registry. GRC team manages publishers via admin API. Evidence submission requires valid JWT from approved issuer; read operations require only OAuth2 Proxy authentication.

**Tech Stack:** Go (Echo framework), PostgreSQL, existing JWTVerifier from ADR-0035

---

## File Structure

### New Files
- `internal/postgres/migrations/019_trusted_publishers.sql` — schema for publishers table
- `internal/auth/publisher_store.go` — PostgreSQL-backed publisher registry
- `internal/auth/publisher_store_test.go` — unit tests for store
- `internal/auth/publisher_middleware.go` — RequireJWT middleware
- `internal/auth/publisher_middleware_test.go` — unit tests for middleware
- `internal/auth/publisher_handlers.go` — admin API handlers

### Modified Files
- `internal/store/handlers_ingest.go` — wire RequireJWT middleware, simplify resolvePublisherIdentity
- `internal/store/store.go` — add Publishers field to Stores struct
- `cmd/gateway/main.go` — initialize PublisherStore, seed from config
- `internal/auth/user_handlers.go` — register admin publisher routes

---

## Task 0: Write Supporting ADRs

**Files:**
- Create: `docs/decisions/0043-publisher-config-schema.md`
- Create: `docs/decisions/0044-admin-role-definition.md`

- [ ] **Step 1: Write ADR-0043 (Publisher Config Schema)**

Create `docs/decisions/0043-publisher-config-schema.md`:

```markdown
# ADR-0043: Publisher Config Schema

- **Status:** Accepted
- **Date:** 2026-05-19

## Problem

Trusted publishers can be managed via admin API at runtime, but production deployments need a way to ship initial publishers (Kyverno, central scanners, K8s service accounts) without requiring manual API calls post-deployment. The schema and format for `PUBLISHER_CONFIG_PATH` YAML file needs to be defined.

## Decision

YAML configuration file with the following schema:

```yaml
publishers:
  - name: string          # Human-readable label
    issuer: string        # JWT iss claim (URL)
    sub: string           # JWT sub claim (identity pattern)
    allowed_types: array  # Optional: artifact types this publisher can submit (null = all)
```

### Example Configuration

```yaml
publishers:
  - name: Kyverno Policy Engine
    issuer: https://kubernetes.default.svc.cluster.local
    sub: system:serviceaccount:kyverno:kyverno
    allowed_types: null

  - name: GitHub Actions Scanner
    issuer: https://token.actions.githubusercontent.com
    sub: repo:acme/scanner:ref:refs/heads/main
    allowed_types:
      - control-catalog
      - evaluation-log

  - name: Central Compliance Scanner
    issuer: https://kubernetes.default.svc.cluster.local
    sub: system:serviceaccount:compliance:scanner
    allowed_types: null
```

### Loading Behavior

On startup, if `PUBLISHER_CONFIG_PATH` environment variable is set:
1. Read YAML file
2. Parse into `[]TrustedPublisher` struct
3. Call `PublisherStore.SeedFromConfig(publishers)`
4. SeedFromConfig uses `INSERT ... ON CONFLICT (issuer, sub) DO NOTHING` (idempotent)
5. Log success/failure

Idempotent design allows:
- Safe pod restarts (no duplicate errors)
- Helm chart upgrades (publishers added, never removed automatically)
- Manual additions via API coexist with config file

### File Location

Deployment-specific. Examples:
- Helm chart: `ConfigMap` mounted at `/etc/complytime/publishers.yaml`
- Docker Compose: volume mount from `deploy/trusted-publishers.yaml`
- Local dev: file in repository root

## Alternatives Considered

### JSON Format
Standard and widely supported, but less human-friendly than YAML for configuration files. Rejected in favor of YAML to match existing config patterns (docker-compose, Helm values).

### TOML Format
More structured than YAML, avoids indentation issues. Rejected because YAML is the standard for Kubernetes/Helm deployments.

### Database-Only (No Config File)
All publishers managed via admin API. Rejected because initial deployment would require manual API calls before system is usable (chicken-and-egg problem for CI/CD pipelines).

### Pattern-Based Trust (e.g., `repo:acme/*`)
Allow glob patterns in `sub` field to trust entire organizations. Rejected for v1 due to security concerns (overly broad trust). May revisit if publisher management becomes bottleneck.

## Consequences

**Upside:**
- Initial publishers ship with deployment (no manual setup)
- Idempotent loading (safe restarts, upgrades)
- YAML is familiar to Kubernetes/Helm users
- Config file + admin API provides flexibility (base set + runtime additions)

**Downside:**
- YAML parsing errors fail silently (logged but don't block startup)
- Config file changes require pod restart (admin API allows runtime changes)
- No pattern matching (each publisher must be individually listed)

## When to Revisit

- **Pattern-based trust needed:** If 100+ publishers with predictable patterns (e.g., all repos in GitHub org)
- **Config validation errors:** If silent YAML parsing failures become operational issue
- **Multi-environment config:** If different environments need different publisher sets (consider separate config files per environment)

## Related Decisions

- ADR-0042: Open Platform with Publisher-Gated Submission
- ADR-0035: Trusted Publisher Evidence (Layer 1/2/3 model)
```

- [ ] **Step 2: Write ADR-0044 (Admin Role Definition)**

Create `docs/decisions/0044-admin-role-definition.md`:

```markdown
# ADR-0044: Admin Role Definition and Privileges

- **Status:** Accepted
- **Date:** 2026-05-19

## Problem

ComplyTime Core has three global roles (`complytime-admin`, `complytime-writer`, `complytime-reviewer`) but their exact privileges are scattered across middleware, handler checks, and comments. This ADR consolidates the role model and defines what each role can do.

## Decision

### Role Hierarchy

```
complytime-admin (highest privilege)
  ↓
complytime-writer
  ↓
complytime-reviewer (lowest privilege)
```

Roles are **not cumulative** — a user has exactly one role, not a set of roles.

### Role Privileges

**`complytime-reviewer` (default for new users)**

Read-only access:
- `GET /api/policies`
- `GET /api/evidence`
- `GET /api/certifications`
- `GET /api/programs`
- `GET /api/catalogs`
- `GET /api/audit-logs`
- All other GET endpoints

Cannot:
- Submit evidence
- Create/modify policies or programs
- Delete anything
- Manage users or publishers

**`complytime-writer`**

All reviewer privileges, plus:
- Submit evidence (if JWT from trusted publisher)
- Create policies: `POST /api/policies`
- Update policies: `PATCH /api/policies/:id`
- Create programs: `POST /api/programs` (if Studio deployed)
- Import/export operations

Cannot:
- Delete evidence, policies, or programs
- Manage users: `PATCH /api/users/:email/role`
- Manage trusted publishers: `/api/admin/publishers`
- Access audit trail: `GET /api/role-changes`

**`complytime-admin`**

All writer privileges, plus:
- Delete operations:
  - `DELETE /api/evidence/:id` (tombstone evidence)
  - `DELETE /api/policies/:id`
  - `DELETE /api/programs/:id`
- User management:
  - `GET /api/users`
  - `PATCH /api/users/:email/role` (promote/demote users)
  - `GET /api/role-changes` (audit trail)
- Publisher management:
  - `POST /api/admin/publishers` (register trusted publisher)
  - `GET /api/admin/publishers` (list publishers)
  - `DELETE /api/admin/publishers/:id` (revoke publisher)

### Enforcement Points

**Middleware:**
- `auth.RequireWrite` — gates POST/PUT/PATCH/DELETE on `/api/*` (allows admin + writer, blocks reviewer)
- `auth.RequireJWT` — gates evidence submission (requires trusted publisher JWT, orthogonal to role)

**Handler-level:**
- Delete operations check `user.Role == consts.RoleAdmin` explicitly
- User management endpoints check `user.Role == consts.RoleAdmin`
- Publisher admin endpoints protected by `RequireWrite` middleware (admin-only in practice)

**Special case:**
- `POST /api/ingest` requires **both** `complytime-writer` role **and** valid JWT from trusted publisher (two-layer gate)

### Role Assignment

**Bootstrap (first user):**
- OAuth2 Proxy header `X-Forwarded-Groups` contains `admin` → auto-promoted to `complytime-admin`
- Logged in `role_changes` table with `changed_by: oauth2-proxy-group-seed`

**Runtime (subsequent users):**
- New users default to `complytime-reviewer`
- Admin promotes via `PATCH /api/users/:email/role`
- Role changes logged in `role_changes` table for audit

**No self-promotion:** Users cannot change their own role (enforced in handler).

## Alternatives Considered

### Cumulative Roles (User Has Multiple Roles)
User could be both `writer` and `reviewer`. Rejected because:
- Writer already implies reader privileges
- Complicates authorization checks (any of these roles vs exact match)
- Doesn't match OAuth2 Proxy / Keycloak role model

### Fine-Grained Permissions (Delete-Policy, Delete-Evidence as Separate Roles)
Allow operators to grant delete-policy without delete-evidence. Rejected for v1:
- Adds complexity (more roles to manage)
- GRC team is small, trusted, single admin role is sufficient
- Can revisit if multi-admin scenarios emerge

### Program-Scoped Admins (Program Owner Role)
User can be admin of specific program, not global admin. Deferred per ADR-0042 (programs are work-tracking, not access boundaries). May revisit if program ownership model changes.

## Consequences

**Upside:**
- Clear privilege boundaries (no ambiguity about "can this role do X?")
- Simple mental model (3 roles, hierarchical)
- Admin role has full control (no partial-admin scenarios)
- Audit trail for all role changes

**Downside:**
- Coarse-grained (can't grant "delete policy but not evidence")
- Single admin role means all admins have full privileges (no scoped delegation)
- Role changes require admin intervention (no self-service promotion)

**Migration:**
- Existing users in database: already have role assigned (no schema change)
- New deployment: first user with `admin` group becomes `complytime-admin`

## When to Revisit

- **Scoped admin needed:** If program owners need delete authority over their program's policies (add program-admin role)
- **Fine-grained delete:** If GRC team wants to grant delete-evidence without delete-policy (split admin role)
- **Self-service promotion:** If teams want writers to self-promote (dangerous, unlikely)

## Related Decisions

- ADR-0042: Open Platform with Publisher-Gated Submission (role enforcement in Layer 1)
- ADR-0022 (Gemara-Hub): Invite-Only Signups (similar role bootstrap pattern)
```

- [ ] **Step 3: Ask user for approval to commit ADRs**

Present ADRs to user and ask: "ADR-0043 and ADR-0044 written. Should I commit these?"

Wait for user approval before proceeding to Task 1.

---

## Task 1: Database Migration

**Files:**
- Create: `internal/postgres/migrations/019_trusted_publishers.sql`

- [ ] **Step 1: Write migration SQL**

Create `internal/postgres/migrations/019_trusted_publishers.sql`:

```sql
-- SPDX-License-Identifier: Apache-2.0

-- Trusted publishers registry for JWT-based evidence submission authorization.
-- Publishers are (issuer, sub) pairs representing approved JWT identities.
CREATE TABLE IF NOT EXISTS trusted_publishers (
  publisher_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sub TEXT NOT NULL,
  allowed_types TEXT[],
  added_by TEXT NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT unique_issuer_sub UNIQUE (issuer, sub)
);

CREATE INDEX IF NOT EXISTS idx_trusted_publishers_issuer ON trusted_publishers(issuer);

COMMENT ON TABLE trusted_publishers IS 'Registry of trusted publisher identities allowed to submit evidence';
COMMENT ON COLUMN trusted_publishers.issuer IS 'JWT iss claim (e.g., https://token.actions.githubusercontent.com)';
COMMENT ON COLUMN trusted_publishers.sub IS 'JWT sub claim (e.g., repo:acme/scanner:ref:refs/heads/main)';
COMMENT ON COLUMN trusted_publishers.allowed_types IS 'Artifact types this publisher can submit (NULL = all types)';
```

- [ ] **Step 2: Test migration**

Run migration against local database:

```bash
POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable" go run cmd/gateway/main.go
```

Expected: Migration runs without error, `trusted_publishers` table exists

Verify table exists:

```bash
psql postgres://complytime:complytime@localhost:5432/complytime -c "\d trusted_publishers"
```

Expected: Table schema displayed

- [ ] **Step 3: Ask user for approval to commit**

Present changes to user:
- File: `internal/postgres/migrations/019_trusted_publishers.sql`
- Description: Database migration for trusted_publishers table

Ask: "Migration 019 ready. Should I commit with message: 'feat: add trusted_publishers table migration'?"

Wait for user approval before proceeding to Task 2.

---

## Task 2: PublisherStore Implementation

**Files:**
- Create: `internal/auth/publisher_store.go`
- Create: `internal/auth/publisher_store_test.go`

- [ ] **Step 1: Write failing test for IsTrusted()**

Create `internal/auth/publisher_store_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/postgres"
)

func TestPublisherStore_IsTrusted(t *testing.T) {
	ctx := context.Background()
	cfg, ok := postgres.ConfigFromEnv()
	if !ok {
		t.Skip("POSTGRES_URL not set")
	}
	client, err := postgres.New(ctx, cfg)
	if err != nil {
		t.Fatalf("postgres connection failed: %v", err)
	}
	defer client.Close()
	if err := client.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	store := auth.NewPublisherStore(client.Pool())

	// Add a trusted publisher
	err = store.AddPublisher(ctx, auth.TrustedPublisher{
		Name:   "Test Publisher",
		Issuer: "https://test.example.com",
		Sub:    "repo:test/repo:ref:refs/heads/main",
		AddedBy: "test@example.com",
	})
	if err != nil {
		t.Fatalf("AddPublisher failed: %v", err)
	}

	// Check trusted publisher
	trusted, err := store.IsTrusted(ctx, "https://test.example.com", "repo:test/repo:ref:refs/heads/main")
	if err != nil {
		t.Fatalf("IsTrusted failed: %v", err)
	}
	if !trusted {
		t.Error("expected publisher to be trusted, got false")
	}

	// Check untrusted publisher
	untrusted, err := store.IsTrusted(ctx, "https://evil.example.com", "repo:evil/repo")
	if err != nil {
		t.Fatalf("IsTrusted failed: %v", err)
	}
	if untrusted {
		t.Error("expected publisher to be untrusted, got true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/auth -run TestPublisherStore_IsTrusted -v
```

Expected: FAIL with "undefined: auth.NewPublisherStore" or "undefined: auth.TrustedPublisher"

- [ ] **Step 3: Write minimal PublisherStore implementation**

Create `internal/auth/publisher_store.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TrustedPublisher represents a JWT identity approved to submit evidence.
type TrustedPublisher struct {
	PublisherID  string
	Name         string
	Issuer       string
	Sub          string
	AllowedTypes []string
	AddedBy      string
	AddedAt      time.Time
}

// PublisherStore manages the trusted publisher registry.
type PublisherStore struct {
	pool *pgxpool.Pool
}

// NewPublisherStore creates a publisher store backed by PostgreSQL.
func NewPublisherStore(pool *pgxpool.Pool) *PublisherStore {
	return &PublisherStore{pool: pool}
}

// IsTrusted checks if the given (issuer, sub) pair is registered as a trusted publisher.
func (s *PublisherStore) IsTrusted(ctx context.Context, issuer, sub string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM trusted_publishers WHERE issuer = $1 AND sub = $2)`,
		issuer, sub,
	).Scan(&exists)
	return exists, err
}

// AddPublisher registers a new trusted publisher.
func (s *PublisherStore) AddPublisher(ctx context.Context, p TrustedPublisher) error {
	id := uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO trusted_publishers (publisher_id, name, issuer, sub, allowed_types, added_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, p.Name, p.Issuer, p.Sub, p.AllowedTypes, p.AddedBy,
	)
	return err
}

// ListPublishers returns all trusted publishers.
func (s *PublisherStore) ListPublishers(ctx context.Context) ([]TrustedPublisher, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT publisher_id, name, issuer, sub, allowed_types, added_by, added_at
		 FROM trusted_publishers
		 ORDER BY added_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var publishers []TrustedPublisher
	for rows.Next() {
		var p TrustedPublisher
		err := rows.Scan(&p.PublisherID, &p.Name, &p.Issuer, &p.Sub, &p.AllowedTypes, &p.AddedBy, &p.AddedAt)
		if err != nil {
			return nil, err
		}
		publishers = append(publishers, p)
	}
	return publishers, rows.Err()
}

// DeletePublisher removes a trusted publisher by ID.
func (s *PublisherStore) DeletePublisher(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM trusted_publishers WHERE publisher_id = $1`, id)
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/auth -run TestPublisherStore_IsTrusted -v
```

Expected: PASS

- [ ] **Step 5: Write test for duplicate publisher constraint**

Add to `internal/auth/publisher_store_test.go`:

```go
func TestPublisherStore_DuplicatePublisher(t *testing.T) {
	ctx := context.Background()
	cfg, ok := postgres.ConfigFromEnv()
	if !ok {
		t.Skip("POSTGRES_URL not set")
	}
	client, err := postgres.New(ctx, cfg)
	if err != nil {
		t.Fatalf("postgres connection failed: %v", err)
	}
	defer client.Close()
	if err := client.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	store := auth.NewPublisherStore(client.Pool())

	publisher := auth.TrustedPublisher{
		Name:   "Duplicate Test",
		Issuer: "https://dup.example.com",
		Sub:    "repo:dup/repo",
		AddedBy: "test@example.com",
	}

	// First insert should succeed
	err = store.AddPublisher(ctx, publisher)
	if err != nil {
		t.Fatalf("first AddPublisher failed: %v", err)
	}

	// Second insert with same (issuer, sub) should fail
	err = store.AddPublisher(ctx, publisher)
	if err == nil {
		t.Error("expected duplicate publisher error, got nil")
	}
}
```

- [ ] **Step 6: Run test to verify duplicate constraint works**

```bash
go test ./internal/auth -run TestPublisherStore_DuplicatePublisher -v
```

Expected: PASS (constraint violation is expected behavior, test checks for error)

- [ ] **Step 7: Commit**

```bash
git add internal/auth/publisher_store.go internal/auth/publisher_store_test.go
git commit -m "feat: add PublisherStore for trusted publisher registry

PostgreSQL-backed store with methods:
- IsTrusted(issuer, sub) checks if publisher is registered
- AddPublisher() inserts new publisher (UNIQUE constraint on issuer+sub)
- ListPublishers() returns all publishers
- DeletePublisher() removes publisher by ID

TDD: tests cover basic operations and duplicate constraint.

Related: ADR-0042 Layer 2"
```

---

## Task 3: RequireJWT Middleware

**Files:**
- Create: `internal/auth/publisher_middleware.go`
- Create: `internal/auth/publisher_middleware_test.go`

- [ ] **Step 1: Write failing test for RequireJWT middleware**

Create `internal/auth/publisher_middleware_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/auth"
)

type mockPublisherStore struct {
	trusted map[string]bool // key = "issuer|sub"
}

func (m *mockPublisherStore) IsTrusted(ctx context.Context, issuer, sub string) (bool, error) {
	key := issuer + "|" + sub
	return m.trusted[key], nil
}

type mockJWTVerifier struct {
	claims *auth.JWTClaims
	err    error
}

func (m *mockJWTVerifier) Verify(ctx context.Context, token string) (*auth.JWTClaims, error) {
	return m.claims, m.err
}

func TestRequireJWT_MissingToken(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	verifier := &mockJWTVerifier{}
	store := &mockPublisherStore{trusted: make(map[string]bool)}
	middleware := auth.RequireJWT(verifier, store)

	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Fatal("expected error for missing token")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T", err)
	}
	if httpErr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", httpErr.Code)
	}
}

func TestRequireJWT_ValidTokenFromTrustedPublisher(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	verifier := &mockJWTVerifier{
		claims: &auth.JWTClaims{
			Iss: "https://test.example.com",
			Sub: "repo:test/repo",
		},
	}
	store := &mockPublisherStore{
		trusted: map[string]bool{
			"https://test.example.com|repo:test/repo": true,
		},
	}
	middleware := auth.RequireJWT(verifier, store)

	called := false
	handler := middleware(func(c echo.Context) error {
		called = true
		identity, ok := auth.PublisherIdentityFrom(c.Request().Context())
		if !ok {
			t.Error("expected PublisherIdentity in context")
		}
		if identity.Issuer != "https://test.example.com" {
			t.Errorf("expected issuer https://test.example.com, got %s", identity.Issuer)
		}
		if identity.Sub != "repo:test/repo" {
			t.Errorf("expected sub repo:test/repo, got %s", identity.Sub)
		}
		if !identity.Verified {
			t.Error("expected Verified=true")
		}
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !called {
		t.Error("next handler was not called")
	}
}

func TestRequireJWT_ValidTokenFromUntrustedPublisher(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	verifier := &mockJWTVerifier{
		claims: &auth.JWTClaims{
			Iss: "https://evil.example.com",
			Sub: "repo:evil/repo",
		},
	}
	store := &mockPublisherStore{trusted: make(map[string]bool)} // empty = no trusted publishers
	middleware := auth.RequireJWT(verifier, store)

	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Fatal("expected error for untrusted publisher")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T", err)
	}
	if httpErr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", httpErr.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/auth -run TestRequireJWT -v
```

Expected: FAIL with "undefined: auth.RequireJWT"

- [ ] **Step 3: Write RequireJWT middleware implementation**

Create `internal/auth/publisher_middleware.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// PublisherIdentity represents a verified JWT identity injected into request context.
type PublisherIdentity struct {
	Sub      string
	Issuer   string
	Type     string
	Verified bool
}

type contextKey string

const publisherIdentityKey contextKey = "publisher_identity"

// PublisherIdentityFrom extracts PublisherIdentity from request context.
func PublisherIdentityFrom(ctx context.Context) (*PublisherIdentity, bool) {
	identity, ok := ctx.Value(publisherIdentityKey).(*PublisherIdentity)
	return identity, ok
}

// PublisherStoreIface defines the minimal interface for publisher verification.
type PublisherStoreIface interface {
	IsTrusted(ctx context.Context, issuer, sub string) (bool, error)
}

// JWTVerifierIface defines the minimal interface for JWT verification.
type JWTVerifierIface interface {
	Verify(ctx context.Context, token string) (*JWTClaims, error)
}

// RequireJWT returns middleware that enforces trusted publisher verification.
// Extracts JWT from Authorization header, verifies signature and claims,
// checks issuer+sub against trusted_publishers table, injects PublisherIdentity
// into context on success, returns 403 on failure.
func RequireJWT(verifier JWTVerifierIface, store PublisherStoreIface) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// 1. Extract Bearer token
			token := extractBearerToken(c.Request())
			if token == "" {
				return echo.NewHTTPError(http.StatusForbidden, map[string]string{
					"error": "trusted publisher JWT required",
				})
			}

			// 2. Verify JWT signature + claims
			claims, err := verifier.Verify(c.Request().Context(), token)
			if err != nil {
				return echo.NewHTTPError(http.StatusForbidden, map[string]string{
					"error": "JWT verification failed",
				})
			}

			// 3. Check if publisher is trusted
			trusted, err := store.IsTrusted(c.Request().Context(), claims.Iss, claims.Sub)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, map[string]string{
					"error": "publisher verification failed",
				})
			}
			if !trusted {
				return echo.NewHTTPError(http.StatusForbidden, map[string]string{
					"error":   "publisher not trusted",
					"issuer":  claims.Iss,
					"subject": claims.Sub,
				})
			}

			// 4. Inject identity into context
			identity := &PublisherIdentity{
				Sub:      claims.Sub,
				Issuer:   claims.Iss,
				Type:     inferTypeFromSub(claims.Sub),
				Verified: true,
			}
			ctx := context.WithValue(c.Request().Context(), publisherIdentityKey, identity)
			c.SetRequest(c.Request().WithContext(ctx))

			return next(c)
		}
	}
}

// extractBearerToken extracts JWT from "Authorization: Bearer <token>" header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

// inferTypeFromSub guesses publisher type from JWT sub claim pattern.
func inferTypeFromSub(sub string) string {
	if strings.HasPrefix(sub, "repo:") {
		return "pipeline"
	}
	if strings.HasPrefix(sub, "system:serviceaccount:") {
		return "service"
	}
	return "unknown"
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/auth -run TestRequireJWT -v
```

Expected: PASS (all 3 tests pass)

- [ ] **Step 5: Commit**

```bash
git add internal/auth/publisher_middleware.go internal/auth/publisher_middleware_test.go
git commit -m "feat: add RequireJWT middleware for publisher verification

Middleware chain:
1. Extract Bearer token from Authorization header
2. Verify JWT signature + claims via JWTVerifier
3. Check (issuer, sub) against PublisherStore
4. Inject PublisherIdentity into context if trusted
5. Return 403 Forbidden if token missing, invalid, or untrusted

TDD: tests cover missing token, valid trusted publisher, valid untrusted publisher.

Related: ADR-0042 Layer 2"
```

---

## Task 4: Admin API Handlers

**Files:**
- Create: `internal/auth/publisher_handlers.go`
- Modify: `internal/auth/user_handlers.go` (register routes)

- [ ] **Step 1: Write test for POST /api/admin/publishers**

Add to `internal/auth/publisher_store_test.go`:

```go
func TestPublisherHandlers_CreatePublisher(t *testing.T) {
	ctx := context.Background()
	cfg, ok := postgres.ConfigFromEnv()
	if !ok {
		t.Skip("POSTGRES_URL not set")
	}
	client, err := postgres.New(ctx, cfg)
	if err != nil {
		t.Fatalf("postgres connection failed: %v", err)
	}
	defer client.Close()
	if err := client.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	store := auth.NewPublisherStore(client.Pool())
	handler := auth.NewPublisherHandlers(store)

	e := echo.New()
	reqBody := `{"name":"Test Publisher","issuer":"https://test.com","sub":"repo:test/repo"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/publishers", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Email", "admin@example.com")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Inject session into context (simulate auth middleware)
	sess := &auth.Session{Email: "admin@example.com"}
	ctx = context.WithValue(req.Context(), "session", sess)
	c.SetRequest(req.WithContext(ctx))

	err = handler.CreatePublisher(c)
	if err != nil {
		t.Fatalf("CreatePublisher failed: %v", err)
	}

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify publisher was created
	trusted, err := store.IsTrusted(ctx, "https://test.com", "repo:test/repo")
	if err != nil {
		t.Fatalf("IsTrusted check failed: %v", err)
	}
	if !trusted {
		t.Error("expected publisher to be trusted after creation")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/auth -run TestPublisherHandlers_CreatePublisher -v
```

Expected: FAIL with "undefined: auth.NewPublisherHandlers"

- [ ] **Step 3: Write publisher handlers implementation**

Create `internal/auth/publisher_handlers.go`:

```go
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// PublisherHandlers provides admin API for managing trusted publishers.
type PublisherHandlers struct {
	store *PublisherStore
}

// NewPublisherHandlers creates publisher admin handlers.
func NewPublisherHandlers(store *PublisherStore) *PublisherHandlers {
	return &PublisherHandlers{store: store}
}

// CreatePublisherRequest is the request body for POST /api/admin/publishers.
type CreatePublisherRequest struct {
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	Sub          string   `json:"sub"`
	AllowedTypes []string `json:"allowed_types"`
}

// CreatePublisher handles POST /api/admin/publishers.
func (h *PublisherHandlers) CreatePublisher(c echo.Context) error {
	var req CreatePublisherRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	if req.Name == "" || req.Issuer == "" || req.Sub == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, issuer, and sub are required")
	}

	sess, ok := SessionFrom(c.Request().Context())
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}

	publisher := TrustedPublisher{
		Name:         req.Name,
		Issuer:       req.Issuer,
		Sub:          req.Sub,
		AllowedTypes: req.AllowedTypes,
		AddedBy:      sess.Email,
	}

	err := h.store.AddPublisher(c.Request().Context(), publisher)
	if err != nil {
		// Check for duplicate constraint violation
		if containsString(err.Error(), "unique_issuer_sub") || containsString(err.Error(), "duplicate key") {
			return echo.NewHTTPError(http.StatusConflict, "publisher with this issuer and sub already exists")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create publisher")
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"message": "publisher created",
	})
}

// ListPublishers handles GET /api/admin/publishers.
func (h *PublisherHandlers) ListPublishers(c echo.Context) error {
	publishers, err := h.store.ListPublishers(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list publishers")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"publishers": publishers,
	})
}

// DeletePublisher handles DELETE /api/admin/publishers/:id.
func (h *PublisherHandlers) DeletePublisher(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "publisher_id required")
	}

	err := h.store.DeletePublisher(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete publisher")
	}

	return c.NoContent(http.StatusNoContent)
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/auth -run TestPublisherHandlers_CreatePublisher -v
```

Expected: PASS

- [ ] **Step 5: Register admin publisher routes**

Modify `internal/auth/user_handlers.go` — find the `RegisterUserAPI` method and add publisher routes:

```go
// RegisterUserAPI mounts user and admin endpoints on /api/*.
func (h *Handler) RegisterUserAPI(g *echo.Group) {
	g.GET("/users", h.listUsersHandler)
	g.PATCH("/users/:email/role", h.updateRoleHandler)
	g.GET("/role-changes", h.listRoleChangesHandler)

	// Publisher admin endpoints (requires complytime-admin role, enforced by RequireWrite middleware)
	if h.publisherHandlers != nil {
		g.POST("/admin/publishers", h.publisherHandlers.CreatePublisher)
		g.GET("/admin/publishers", h.publisherHandlers.ListPublishers)
		g.DELETE("/admin/publishers/:id", h.publisherHandlers.DeletePublisher)
	}
}
```

Also add a field to the `Handler` struct and a setter method:

```go
type Handler struct {
	users             UserStore
	publisherHandlers *PublisherHandlers
}

// SetPublisherHandlers configures the publisher admin handlers.
func (h *Handler) SetPublisherHandlers(ph *PublisherHandlers) {
	h.publisherHandlers = ph
}
```

- [ ] **Step 6: Commit**

```bash
git add internal/auth/publisher_handlers.go internal/auth/user_handlers.go
git commit -m "feat: add admin API for trusted publisher management

Handlers:
- POST /api/admin/publishers (create publisher, requires admin)
- GET /api/admin/publishers (list publishers, requires admin)
- DELETE /api/admin/publishers/:id (delete publisher, requires admin)

All routes protected by RequireWrite middleware (complytime-admin role).

TDD: test covers create publisher endpoint.

Related: ADR-0042"
```

---

## Task 5: Wire Middleware and Simplify Ingest Handler

**Files:**
- Modify: `internal/store/handlers_ingest.go`
- Modify: `internal/store/store.go`
- Modify: `cmd/gateway/main.go`

- [ ] **Step 1: Add Publishers field to Stores struct**

Modify `internal/store/store.go` — add `Publishers` field:

```go
type Stores struct {
	Policies            PolicyStore
	Mappings            MappingStore
	Evidence            EvidenceStore
	Blob                blob.BlobStore
	AuditLogs           AuditLogStore
	DraftAuditLogs      DraftAuditLogStore
	Requirements        RequirementStore
	Controls            ControlStore
	Guidance            GuidanceStore
	Threats             ThreatStore
	Risks               RiskStore
	Catalogs            CatalogStore
	EvidenceAssessments EvidenceAssessmentStore
	Certifications      CertificationStore
	EventPublisher      EventPublisher
	HealthChecker       HealthChecker
	Inventory           InventoryStore
	Users               UserStore
	Registry            *RegistryConfig
	IngestTracker       *IngestTracker
	IngestPublisher     IngestRawPublisher
	JWTVerifier         *auth.JWTVerifier
	Publishers          *auth.PublisherStore  // Add this line
}
```

- [ ] **Step 2: Wire RequireJWT middleware to /api/ingest route**

Modify `internal/store/handlers_ingest.go` — update `registerIngestRoutes`:

```go
func registerIngestRoutes(g *echo.Group, s Stores) {
	// Apply RequireJWT middleware only to POST /api/ingest
	var ingestMiddleware []echo.MiddlewareFunc
	if s.JWTVerifier != nil && s.Publishers != nil {
		ingestMiddleware = append(ingestMiddleware, auth.RequireJWT(s.JWTVerifier, s.Publishers))
	}

	g.POST("/ingest",
		echo.WrapHandler(IngestAsyncHandler(s.IngestPublisher, s.IngestTracker, s.JWTVerifier)),
		ingestMiddleware...,
	)

	g.GET("/ingest/jobs/:job_id", IngestJobStatusHandler(s.IngestTracker))
}
```

- [ ] **Step 3: Simplify resolvePublisherIdentity to read from context**

Modify `internal/store/handlers_ingest.go` — replace `resolvePublisherIdentity`:

```go
// resolvePublisherIdentity extracts publisher identity from request context.
// RequireJWT middleware guarantees identity exists and is verified.
func resolvePublisherIdentity(r *http.Request, verifier *auth.JWTVerifier) events.PublisherIdentity {
	identity, ok := auth.PublisherIdentityFrom(r.Context())
	if !ok {
		// Fallback for requests that bypass middleware (should not happen in production)
		email := r.Header.Get("X-Forwarded-Email")
		ptype := ""
		if email != "" {
			ptype = "user"
		}
		return events.PublisherIdentity{
			SubmittedBy: email,
			Type:        ptype,
			Verified:    false,
		}
	}

	return events.PublisherIdentity{
		SubmittedBy: identity.Sub,
		Issuer:      identity.Issuer,
		Type:        identity.Type,
		Verified:    true,
	}
}
```

- [ ] **Step 4: Initialize PublisherStore in main.go**

Modify `cmd/gateway/main.go` — initialize PublisherStore and wire it into Stores struct:

Find the section where `stores := store.Stores{...}` is defined and add:

```go
	publisherStore := auth.NewPublisherStore(pgClient.Pool())

	stores := store.Stores{
		Policies:            st,
		Mappings:            st,
		Evidence:            st,
		Blob:                blobStore,
		AuditLogs:           st,
		DraftAuditLogs:      st,
		Requirements:        st,
		Controls:            st,
		Guidance:            st,
		Threats:             st,
		Risks:               st,
		Catalogs:            st,
		EvidenceAssessments: st,
		Certifications:      st,
		EventPublisher:      pub,
		HealthChecker:       pgClient,
		Inventory:           st,
		Users:               pgClient,
		Registry:            registryConfig,
		IngestTracker:       ingestTracker,
		IngestPublisher:     bus,
		JWTVerifier:         jwtVerifier,
		Publishers:          publisherStore,  // Add this line
	}
```

Also wire publisher handlers to authHandler:

```go
	authHandler := auth.NewHandler()
	authHandler.SetUserStore(pgClient)
	
	publisherHandlers := auth.NewPublisherHandlers(publisherStore)
	authHandler.SetPublisherHandlers(publisherHandlers)
```

- [ ] **Step 5: Test evidence submission requires JWT**

Start the gateway:

```bash
POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable" \
NATS_URL="nats://localhost:4222" \
go run cmd/gateway/main.go
```

In another terminal, test submission without JWT:

```bash
curl -X POST http://localhost:8080/api/ingest \
  -H "Content-Type: application/yaml" \
  -H "X-Forwarded-Email: user@example.com" \
  -d "metadata: {type: evaluation-log}"
```

Expected: `403 Forbidden` with error "trusted publisher JWT required"

- [ ] **Step 6: Commit**

```bash
git add internal/store/handlers_ingest.go internal/store/store.go cmd/gateway/main.go
git commit -m "feat: wire RequireJWT middleware to evidence submission

Changes:
- Add Publishers field to Stores struct
- Apply RequireJWT middleware to POST /api/ingest
- Simplify resolvePublisherIdentity (reads from context)
- Initialize PublisherStore in main.go
- Wire PublisherHandlers to authHandler

Evidence submission now requires valid JWT from trusted publisher.
Fallback to X-Forwarded-Email only if middleware not configured.

Related: ADR-0042 Layer 2 enforcement"
```

---

## Task 6: Config Seeding on Startup

**Files:**
- Modify: `internal/auth/publisher_store.go` (add SeedFromConfig method)
- Modify: `cmd/gateway/main.go` (seed publishers from YAML on startup)

- [ ] **Step 1: Add SeedFromConfig method to PublisherStore**

Modify `internal/auth/publisher_store.go` — add method:

```go
// SeedFromConfig upserts publishers from config file (idempotent).
// Uses ON CONFLICT DO NOTHING to avoid duplicate errors on restart.
func (s *PublisherStore) SeedFromConfig(ctx context.Context, publishers []TrustedPublisher) error {
	for _, p := range publishers {
		_, err := s.pool.Exec(ctx,
			`INSERT INTO trusted_publishers (publisher_id, name, issuer, sub, allowed_types, added_by, added_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, 'config-seed', NOW())
			 ON CONFLICT (issuer, sub) DO NOTHING`,
			p.Name, p.Issuer, p.Sub, p.AllowedTypes,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 2: Add config loading in main.go**

Modify `cmd/gateway/main.go` — add publisher config seeding after PublisherStore initialization:

```go
	publisherStore := auth.NewPublisherStore(pgClient.Pool())

	// Seed trusted publishers from config file if present
	if cfgPath := os.Getenv("PUBLISHER_CONFIG_PATH"); cfgPath != "" {
		if pubConfig, err := auth.LoadPublisherConfig(cfgPath); err == nil && pubConfig != nil {
			seedPublishers := make([]auth.TrustedPublisher, len(pubConfig.Publishers))
			for i, p := range pubConfig.Publishers {
				seedPublishers[i] = auth.TrustedPublisher{
					Name:         p.Name,
					Issuer:       p.Issuer,
					Sub:          p.Sub,
					AllowedTypes: p.AllowedTypes,
				}
			}
			if err := publisherStore.SeedFromConfig(ctx, seedPublishers); err != nil {
				slog.Warn("publisher config seed failed", "path", cfgPath, "error", err)
			} else {
				slog.Info("seeded trusted publishers from config", "path", cfgPath, "count", len(seedPublishers))
			}
		}
	}
```

- [ ] **Step 3: Test config seeding**

Create a test config file `test-publishers.yaml`:

```yaml
publishers:
  - name: Test Publisher
    issuer: https://test.example.com
    sub: repo:test/repo:ref:refs/heads/main
    allowed_types: null
```

Start gateway with config:

```bash
POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable" \
NATS_URL="nats://localhost:4222" \
PUBLISHER_CONFIG_PATH="test-publishers.yaml" \
go run cmd/gateway/main.go
```

Expected: Log message "seeded trusted publishers from config" with count=1

Verify publisher exists in database:

```bash
psql postgres://complytime:complytime@localhost:5432/complytime \
  -c "SELECT name, issuer, sub FROM trusted_publishers WHERE added_by='config-seed';"
```

Expected: Row with "Test Publisher" entry

- [ ] **Step 4: Commit**

```bash
git add internal/auth/publisher_store.go cmd/gateway/main.go
git commit -m "feat: seed trusted publishers from config on startup

Add SeedFromConfig method with idempotent upsert (ON CONFLICT DO NOTHING).
Load publishers from PUBLISHER_CONFIG_PATH env var on startup.

Allows shipping base publishers (Kyverno, central scanners) in Helm chart.
GRC team can add more via admin API without redeploying.

Related: ADR-0042"
```

---

## Task 7: Integration Test

**Files:**
- Modify: `internal/integration/auth_flow_test.go` (or create if doesn't exist)

- [ ] **Step 1: Write integration test for full publisher flow**

Create or modify `internal/integration/auth_flow_test.go`:

```go
//go:build integration
// +build integration

// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/postgres"
)

func TestPublisherFlow_EndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg, ok := postgres.ConfigFromEnv()
	if !ok {
		t.Skip("POSTGRES_URL not set")
	}

	client, err := postgres.New(ctx, cfg)
	if err != nil {
		t.Fatalf("postgres connection failed: %v", err)
	}
	defer client.Close()
	if err := client.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	publisherStore := auth.NewPublisherStore(client.Pool())

	// Step 1: Register a trusted publisher via admin API
	publisher := auth.TrustedPublisher{
		Name:    "Integration Test Publisher",
		Issuer:  "https://integration.example.com",
		Sub:     "repo:integration/test:ref:refs/heads/main",
		AddedBy: "admin@example.com",
	}
	err = publisherStore.AddPublisher(ctx, publisher)
	if err != nil {
		t.Fatalf("failed to add publisher: %v", err)
	}

	// Step 2: Verify publisher is trusted
	trusted, err := publisherStore.IsTrusted(ctx, publisher.Issuer, publisher.Sub)
	if err != nil {
		t.Fatalf("IsTrusted check failed: %v", err)
	}
	if !trusted {
		t.Error("expected publisher to be trusted after registration")
	}

	// Step 3: List publishers and verify it appears
	publishers, err := publisherStore.ListPublishers(ctx)
	if err != nil {
		t.Fatalf("ListPublishers failed: %v", err)
	}
	found := false
	for _, p := range publishers {
		if p.Issuer == publisher.Issuer && p.Sub == publisher.Sub {
			found = true
			if p.Name != publisher.Name {
				t.Errorf("expected name %q, got %q", publisher.Name, p.Name)
			}
			if p.AddedBy != publisher.AddedBy {
				t.Errorf("expected added_by %q, got %q", publisher.AddedBy, p.AddedBy)
			}
			break
		}
	}
	if !found {
		t.Error("publisher not found in list")
	}

	// Step 4: Delete publisher
	var publisherID string
	for _, p := range publishers {
		if p.Issuer == publisher.Issuer && p.Sub == publisher.Sub {
			publisherID = p.PublisherID
			break
		}
	}
	err = publisherStore.DeletePublisher(ctx, publisherID)
	if err != nil {
		t.Fatalf("DeletePublisher failed: %v", err)
	}

	// Step 5: Verify publisher is no longer trusted
	trusted, err = publisherStore.IsTrusted(ctx, publisher.Issuer, publisher.Sub)
	if err != nil {
		t.Fatalf("IsTrusted check failed: %v", err)
	}
	if trusted {
		t.Error("expected publisher to be untrusted after deletion")
	}
}
```

- [ ] **Step 2: Run integration test**

```bash
POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable" \
go test ./internal/integration -tags=integration -run TestPublisherFlow_EndToEnd -v
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/integration/auth_flow_test.go
git commit -m "test: add end-to-end integration test for publisher flow

Test covers:
1. Register trusted publisher via store
2. Verify publisher is trusted
3. List publishers and verify it appears
4. Delete publisher
5. Verify publisher is no longer trusted

Run with: go test -tags=integration ./internal/integration

Related: ADR-0042"
```

---

## Task 8: Update Documentation

**Files:**
- Modify: `README.md` or `docs/authentication.md` (document PUBLISHER_CONFIG_PATH)

- [ ] **Step 1: Document PUBLISHER_CONFIG_PATH environment variable**

Add to `.env.example`:

```bash
# Trusted publisher configuration (optional). Path to YAML file containing
# initial trusted publishers to seed on startup. GRC team can add more via
# admin API at runtime.
# PUBLISHER_CONFIG_PATH=deploy/trusted-publishers.yaml
```

- [ ] **Step 2: Document admin API endpoints**

Add to architecture docs or create `docs/admin-api.md`:

```markdown
## Trusted Publisher Admin API

**Authentication:** All endpoints require `complytime-admin` role.

### POST /api/admin/publishers

Register a new trusted publisher (issuer + sub pair).

**Request:**
```json
{
  "name": "GitHub Actions Scanner",
  "issuer": "https://token.actions.githubusercontent.com",
  "sub": "repo:acme/scanner:ref:refs/heads/main",
  "allowed_types": null
}
```

**Response:** `201 Created`

**Errors:**
- `409 Conflict` — publisher already exists
- `403 Forbidden` — caller lacks admin role

### GET /api/admin/publishers

List all trusted publishers.

**Response:** `200 OK`
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

### DELETE /api/admin/publishers/:id

Remove a trusted publisher.

**Response:** `204 No Content`

**Note:** Deleting a publisher does NOT invalidate existing evidence submitted by that publisher.
```

- [ ] **Step 3: Commit**

```bash
git add .env.example docs/admin-api.md
git commit -m "docs: document trusted publisher admin API and config

Add PUBLISHER_CONFIG_PATH to .env.example
Document admin endpoints: POST/GET/DELETE /api/admin/publishers

Related: ADR-0042"
```

---

## Summary

**Total Tasks:** 8  
**Estimated Time:** 2-3 hours

**Key Files Created:**
- `internal/postgres/migrations/019_trusted_publishers.sql`
- `internal/auth/publisher_store.go` + tests
- `internal/auth/publisher_middleware.go` + tests
- `internal/auth/publisher_handlers.go`
- `internal/integration/auth_flow_test.go`

**Key Files Modified:**
- `internal/store/handlers_ingest.go` (wire middleware, simplify identity extraction)
- `internal/store/store.go` (add Publishers field)
- `cmd/gateway/main.go` (initialize store, seed config, wire handlers)
- `internal/auth/user_handlers.go` (register admin routes)

**Testing Strategy:**
- Unit tests for PublisherStore (IsTrusted, AddPublisher, duplicate constraint)
- Unit tests for RequireJWT middleware (missing token, valid trusted, valid untrusted)
- Unit test for admin handler (create publisher)
- Integration test for full flow (register → verify → list → delete)

**Next Steps:**
After implementation, test the full flow:
1. Start gateway with test config
2. Register publisher via admin API
3. Submit evidence with valid JWT from trusted publisher
4. Verify evidence has `publisher_verified=true`
5. Attempt submission without JWT → 403
6. Attempt submission with JWT from untrusted publisher → 403
