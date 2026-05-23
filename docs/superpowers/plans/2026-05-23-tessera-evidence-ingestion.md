# Tessera-Based Evidence Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace database-first evidence storage with Tessera transparency log as source of truth

**Architecture:** Evidence submitted via JWT-authenticated API → appended to Tessera log → async processing to PostgreSQL → independent witness verification → checkpoint countersigning

**Tech Stack:** Tessera (transparency-dev/tessera), PostgreSQL (query layer), NATS (event bus), Go 1.22+, Gemara (evidence format)

---

## File Structure

### New Files Created

**Tessera Client Package:**
- `internal/tessera/client.go` - Tessera appender/reader wrapper
- `internal/tessera/client_test.go` - Unit tests for client
- `internal/tessera/options.go` - Configuration options

**JWT Authentication:**
- `internal/auth/jwt.go` - OIDC token verification
- `internal/auth/jwt_test.go` - JWT verification tests

**Witness Service:**
- `cmd/witness/main.go` - Service entry point
- `cmd/witness/config.go` - Configuration parsing
- `cmd/witness/state.go` - State persistence
- `cmd/witness/verifier.go` - Entry verification logic
- `cmd/witness/verifier_test.go` - Verification tests

**Database:**
- `migrations/019_add_log_index.sql` - Add log_index column

**Testing:**
- `internal/store/evidence_integration_test.go` - End-to-end ingestion test
- `testdata/gemara/valid-evaluation-log.yaml` - Test fixture
- `testdata/gemara/valid-enforcement-log.yaml` - Test fixture
- `testdata/gemara/valid-policy.yaml` - Test fixture
- `testdata/gemara/malformed.yaml` - Invalid test fixture

**Deployment:**
- `deploy/k8s/witness-deployment.yaml` - Witness K8s deployment
- `deploy/k8s/witness-config.yaml` - ConfigMap example
- `deploy/k8s/tessera-pvc.yaml` - PersistentVolumeClaim

### Files Modified

- `internal/store/handlers_ingest.go` - Add Tessera integration
- `internal/store/stores.go` - Add TesseraAppender field
- `internal/events/ingest.go` - Add LogIndex to IngestEvent
- `internal/workers/ingest_worker.go` - Store log_index in PostgreSQL
- `cmd/gateway/main.go` - Initialize Tessera client
- `go.mod` / `go.sum` - Add Tessera dependencies

---

## Task 1: PostgreSQL Migration - Add log_index Column

**Files:**
- Create: `migrations/019_add_log_index.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- migrations/019_add_log_index.sql
-- Add Tessera log_index to evidence table

-- Add log_index column (nullable for backward compatibility)
ALTER TABLE evidence ADD COLUMN log_index BIGINT;

-- Index for efficient lookup by log_index
CREATE INDEX idx_evidence_log_index ON evidence(log_index);

-- Comments
COMMENT ON COLUMN evidence.log_index IS 'Tessera transparency log position (NULL for pre-Tessera evidence)';
```

- [ ] **Step 2: Verify migration file created**

Run: `ls -la migrations/019_add_log_index.sql`
Expected: File exists

- [ ] **Step 3: Test migration (up)**

Run: `psql -h localhost -U complytime_test -d complytime_test -f migrations/019_add_log_index.sql`
Expected: `ALTER TABLE` and `CREATE INDEX` success

- [ ] **Step 4: Verify schema change**

Run: `psql -h localhost -U complytime_test -d complytime_test -c "\d evidence"`
Expected: Column `log_index | bigint` appears in table definition

- [ ] **Step 5: Verify index created**

Run: `psql -h localhost -U complytime_test -d complytime_test -c "\d idx_evidence_log_index"`
Expected: Index definition shows `btree (log_index)`

- [ ] **Step 6: Commit**

```bash
git add migrations/019_add_log_index.sql
git commit -m "feat: add log_index column for Tessera integration

- Add nullable BIGINT column to evidence table
- Add index for efficient log_index lookups
- Nullable for backward compatibility with pre-Tessera evidence

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: NATS Message Schema - Add log_index Field

**Files:**
- Modify: `internal/events/ingest.go`
- Modify: `internal/workers/ingest_worker.go`

- [ ] **Step 1: Write test for updated IngestEvent schema**

```go
// internal/events/ingest_test.go
package events_test

import (
	"encoding/json"
	"testing"

	"github.com/complytime/core/internal/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngestEvent_JSONSerialization(t *testing.T) {
	original := events.IngestEvent{
		JobID:    "job-123",
		LogIndex: 42,
		YAML:     []byte("metadata:\n  type: EvaluationLog"),
		PublisherIdentity: events.PublisherIdentity{
			Sub:      "repo:complytime/scanner:ref:refs/heads/main",
			Issuer:   "https://token.actions.githubusercontent.com",
			Type:     "pipeline",
			Verified: true,
		},
	}

	// Serialize
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Deserialize
	var decoded events.IngestEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.LogIndex, decoded.LogIndex)
	assert.Equal(t, original.YAML, decoded.YAML)
	assert.Equal(t, original.PublisherIdentity, decoded.PublisherIdentity)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/events -v -run TestIngestEvent_JSONSerialization`
Expected: FAIL with "unknown field 'LogIndex'" or similar compilation error

- [ ] **Step 3: Add LogIndex field to IngestEvent**

```go
// internal/events/ingest.go
package events

type IngestEvent struct {
	JobID             string            `json:"job_id"`
	LogIndex          uint64            `json:"log_index"`          // NEW: Tessera position
	YAML              []byte            `json:"yaml"`
	PublisherIdentity PublisherIdentity `json:"publisher_identity"`
}

type PublisherIdentity struct {
	Sub      string `json:"sub"`      // JWT sub claim
	Issuer   string `json:"issuer"`   // JWT iss claim
	Type     string `json:"type"`     // "pipeline" or "service"
	Verified bool   `json:"verified"` // Always true after JWT verification
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/events -v -run TestIngestEvent_JSONSerialization`
Expected: PASS

- [ ] **Step 5: Update IngestWorker to use log_index**

```go
// internal/workers/ingest_worker.go
// Find the INSERT statement (around line 120) and add log_index column

func (w *IngestWorker) processEvent(ctx context.Context, evt events.IngestEvent) error {
	// ... existing YAML parsing logic ...

	// Insert to PostgreSQL - add log_index
	for _, row := range rows {
		_, err := w.db.Exec(ctx,
			`INSERT INTO evidence 
			 (evidence_id, policy_id, target_id, source_registry, executor, 
			  eval_result, collected_at, log_index, publisher_issuer, submitted_by, publisher_type)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			row.EvidenceID,
			row.PolicyID,
			row.TargetID,
			row.SourceRegistry,
			row.Executor,
			row.EvalResult,
			row.CollectedAt,
			evt.LogIndex,                     // NEW
			evt.PublisherIdentity.Issuer,     // NEW
			evt.PublisherIdentity.Sub,        // NEW
			evt.PublisherIdentity.Type,       // NEW
		)
		if err != nil {
			return fmt.Errorf("insert evidence: %w", err)
		}
	}

	return nil
}
```

- [ ] **Step 6: Commit**

```bash
git add internal/events/ingest.go internal/events/ingest_test.go internal/workers/ingest_worker.go
git commit -m "feat: add log_index to NATS IngestEvent schema

- Add LogIndex uint64 field to IngestEvent
- Add JSON serialization test
- Update IngestWorker to store log_index in PostgreSQL
- Add publisher_issuer, submitted_by, publisher_type columns

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Tessera Client Package

**Files:**
- Create: `internal/tessera/options.go`
- Create: `internal/tessera/client.go`
- Create: `internal/tessera/client_test.go`

- [ ] **Step 1: Add Tessera dependency**

```bash
go get github.com/transparency-dev/tessera@latest
go get github.com/transparency-dev/tessera/storage/posix@latest
go mod tidy
```

- [ ] **Step 2: Verify dependency added**

Run: `go list -m github.com/transparency-dev/tessera`
Expected: `github.com/transparency-dev/tessera vX.Y.Z`

- [ ] **Step 3: Write options types**

```go
// internal/tessera/options.go
package tessera

import "time"

type Options struct {
	CheckpointTime time.Duration // Checkpoint interval (e.g., 10m)
	CheckpointSize int           // Checkpoint batch size (e.g., 100 entries)
}

func DefaultOptions() Options {
	return Options{
		CheckpointTime: 10 * time.Minute,
		CheckpointSize: 100,
	}
}
```

- [ ] **Step 4: Write failing test for Tessera client**

```go
// internal/tessera/client_test.go
package tessera_test

import (
	"context"
	"testing"

	"github.com/complytime/core/internal/tessera"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Add_SequentialIndices(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	client, err := tessera.NewClient(ctx, tmpDir, tessera.DefaultOptions())
	require.NoError(t, err)
	defer client.Close()

	// Add first entry
	idx1, err := client.Add(ctx, []byte("entry 1"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), idx1)

	// Add second entry
	idx2, err := client.Add(ctx, []byte("entry 2"))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), idx2)

	// Add third entry
	idx3, err := client.Add(ctx, []byte("entry 3"))
	require.NoError(t, err)
	assert.Equal(t, uint64(2), idx3)
}

func TestClient_Read_ReturnsStoredEntry(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	client, err := tessera.NewClient(ctx, tmpDir, tessera.DefaultOptions())
	require.NoError(t, err)
	defer client.Close()

	// Add entry
	entry := []byte("test evidence yaml")
	idx, err := client.Add(ctx, entry)
	require.NoError(t, err)

	// Read entry back
	retrieved, err := client.Read(ctx, idx)
	require.NoError(t, err)
	assert.Equal(t, entry, retrieved)
}
```

- [ ] **Step 5: Run test to verify it fails**

Run: `go test ./internal/tessera -v`
Expected: FAIL with "package tessera is not in std" or "undefined: NewClient"

- [ ] **Step 6: Implement Tessera client**

```go
// internal/tessera/client.go
package tessera

import (
	"context"
	"fmt"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
)

type Client struct {
	storage  *posix.Storage
	shutdown func()
}

func NewClient(ctx context.Context, storagePath string, opts Options) (*Client, error) {
	// Initialize POSIX storage
	storage, err := posix.New(ctx, storagePath, posix.WithBatching(opts.CheckpointSize, opts.CheckpointSize))
	if err != nil {
		return nil, fmt.Errorf("init POSIX storage: %w", err)
	}

	return &Client{
		storage:  storage,
		shutdown: func() { _ = storage.Close() },
	}, nil
}

func (c *Client) Add(ctx context.Context, entry []byte) (uint64, error) {
	future := c.storage.Add(ctx, tessera.NewEntry(entry))
	idx, err := future()
	if err != nil {
		return 0, fmt.Errorf("tessera add: %w", err)
	}
	return idx, nil
}

func (c *Client) Read(ctx context.Context, index uint64) ([]byte, error) {
	entry, err := c.storage.Get(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("tessera read: %w", err)
	}
	return entry, nil
}

func (c *Client) Close() error {
	if c.shutdown != nil {
		c.shutdown()
	}
	return nil
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/tessera -v`
Expected: PASS (both tests pass)

- [ ] **Step 8: Commit**

```bash
git add internal/tessera/ go.mod go.sum
git commit -m "feat: implement Tessera client wrapper

- Add POSIX storage client with Add/Read operations
- Add Options for checkpoint configuration
- Add unit tests for sequential indexing and read-after-write
- Use transparency-dev/tessera library

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: JWT Verification Package

**Files:**
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/jwt_test.go`

- [ ] **Step 1: Add JWT dependencies**

```bash
go get github.com/golang-jwt/jwt/v5@latest
go get github.com/lestrrat-go/jwx/v2@latest
go mod tidy
```

- [ ] **Step 2: Write test for JWT verification**

```go
// internal/auth/jwt_test.go
package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/complytime/core/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTVerifier_Verify_ValidToken(t *testing.T) {
	// Setup: Create test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Setup: Mock JWKS endpoint
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return public key in JWKS format
		w.Write([]byte(`{
			"keys": [{
				"kty": "EC",
				"use": "sig",
				"kid": "test-key-1",
				"crv": "P-256",
				"x": "..." ,
				"y": "..."
			}]
		}`))
	}))
	defer jwksServer.Close()

	// Create verifier
	verifier := auth.NewJWTVerifier([]string{jwksServer.URL})

	// Create valid JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": jwksServer.URL,
		"sub": "repo:complytime/scanner:ref:refs/heads/main",
		"aud": "complytime-core",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// Verify token
	claims, err := verifier.Verify(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, jwksServer.URL, claims.Iss)
	assert.Equal(t, "repo:complytime/scanner:ref:refs/heads/main", claims.Sub)
}

func TestJWTVerifier_Verify_ExpiredToken(t *testing.T) {
	// Setup: Create expired token
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:complytime/scanner:ref:refs/heads/main",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(privateKey)

	verifier := auth.NewJWTVerifier([]string{"https://token.actions.githubusercontent.com"})

	// Verify fails
	_, err := verifier.Verify(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestJWTVerifier_Verify_UnknownIssuer(t *testing.T) {
	verifier := auth.NewJWTVerifier([]string{"https://token.actions.githubusercontent.com"})

	// Token from unknown issuer
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://untrusted-issuer.example.com",
		"sub": "malicious-actor",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, _ := token.SignedString(privateKey)

	// Verify fails
	_, err := verifier.Verify(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer not allowed")
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/auth -v`
Expected: FAIL with "undefined: NewJWTVerifier"

- [ ] **Step 4: Implement JWT verifier**

```go
// internal/auth/jwt.go
package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWTClaims struct {
	Iss string // Issuer
	Sub string // Subject
	Aud string // Audience
	Exp int64  // Expiration
	Iat int64  // Issued At
}

type JWTVerifier struct {
	allowedIssuers map[string]bool
	cache          jwk.Cache
}

func NewJWTVerifier(allowedIssuers []string) *JWTVerifier {
	issuerMap := make(map[string]bool)
	for _, iss := range allowedIssuers {
		issuerMap[iss] = true
	}

	return &JWTVerifier{
		allowedIssuers: issuerMap,
		cache:          jwk.NewCache(context.Background()),
	}
}

func (v *JWTVerifier) Verify(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// Parse token without verification first
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Extract issuer claim
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid claims format")
		}

		issuer, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("missing issuer claim")
		}

		// Check if issuer is allowed
		if !v.allowedIssuers[issuer] {
			return nil, fmt.Errorf("issuer not allowed: %s", issuer)
		}

		// Fetch JWKS from issuer
		jwksURL := issuer + "/.well-known/jwks"
		keySet, err := v.cache.Get(ctx, jwksURL)
		if err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}

		// Find matching key
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		key, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key not found: %s", kid)
		}

		// Convert to crypto.PublicKey
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("extract public key: %w", err)
		}

		return rawKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("verify JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return &JWTClaims{
		Iss: claims["iss"].(string),
		Sub: claims["sub"].(string),
		Aud: claims["aud"].(string),
		Exp: int64(claims["exp"].(float64)),
		Iat: int64(claims["iat"].(float64)),
	}, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/auth -v`
Expected: PASS (all 3 tests pass)

- [ ] **Step 6: Commit**

```bash
git add internal/auth/ go.mod go.sum
git commit -m "feat: implement JWT verification with JWKS discovery

- Add JWTVerifier with issuer allowlist
- Implement JWKS fetching and caching
- Add tests for valid/expired/unknown-issuer scenarios
- Use golang-jwt and lestrrat-go/jwx libraries

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Gateway Ingestion - Tessera Integration

**Files:**
- Modify: `internal/store/stores.go`
- Modify: `internal/store/handlers_ingest.go`
- Modify: `cmd/gateway/main.go`

- [ ] **Step 1: Add TesseraAppender interface to Stores**

```go
// internal/store/stores.go
package store

// Add after existing interfaces
type TesseraAppender interface {
	Add(ctx context.Context, entry []byte) (uint64, error)
}

type Stores struct {
	// ... existing fields ...
	TesseraAppender TesseraAppender // NEW
}
```

- [ ] **Step 2: Write test for refactored ingestion handler**

```go
// internal/store/handlers_ingest_test.go (add new test)
func TestIngestAsyncHandler_WithTessera(t *testing.T) {
	// Setup: Mock Tessera appender
	mockTessera := &mockTesseraAppender{
		nextIndex: 0,
		entries:   make(map[uint64][]byte),
	}

	// Setup: Mock JWT verifier (returns valid claims)
	mockVerifier := &mockJWTVerifier{
		claims: &auth.JWTClaims{
			Iss: "https://token.actions.githubusercontent.com",
			Sub: "repo:complytime/scanner:ref:refs/heads/main",
		},
	}

	// Setup: Mock NATS publisher
	mockNATS := &mockIngestPublisher{
		published: make([]events.IngestEvent, 0),
	}

	// Setup: IngestTracker
	tracker := NewIngestTracker()

	// Create handler
	handler := IngestAsyncHandler(mockNATS, tracker, mockVerifier, mockTessera)

	// Submit evidence with JWT
	evidenceYAML := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: test")
	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewReader(evidenceYAML))
	req.Header.Set("Authorization", "Bearer mock-jwt-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify: 202 Accepted
	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Verify: Response contains log_index
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, float64(0), resp["log_index"])
	assert.NotEmpty(t, resp["job_id"])

	// Verify: Evidence in Tessera
	assert.Equal(t, evidenceYAML, mockTessera.entries[0])

	// Verify: NATS message published with log_index
	assert.Len(t, mockNATS.published, 1)
	assert.Equal(t, uint64(0), mockNATS.published[0].LogIndex)
	assert.Equal(t, evidenceYAML, mockNATS.published[0].YAML)
}

func TestIngestAsyncHandler_JWTVerificationFails(t *testing.T) {
	mockVerifier := &mockJWTVerifier{
		shouldFail: true,
	}
	mockTessera := &mockTesseraAppender{}
	mockNATS := &mockIngestPublisher{}
	tracker := NewIngestTracker()

	handler := IngestAsyncHandler(mockNATS, tracker, mockVerifier, mockTessera)

	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewReader([]byte("evidence")))
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify: 403 Forbidden
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Verify: Evidence NOT in Tessera
	assert.Empty(t, mockTessera.entries)

	// Verify: NATS message NOT published
	assert.Empty(t, mockNATS.published)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/store -v -run TestIngestAsyncHandler`
Expected: FAIL with "function signature mismatch" or "undefined: IngestAsyncHandler"

- [ ] **Step 4: Refactor IngestAsyncHandler to use Tessera**

```go
// internal/store/handlers_ingest.go
package store

import (
	"fmt"
	"io"
	"net/http"

	"github.com/complytime/core/internal/auth"
	"github.com/complytime/core/internal/events"
	"github.com/complytime/core/pkg/httputil"
	"github.com/google/uuid"
)

const MaxRequestBody = 10 * 1024 * 1024 // 10MB

func IngestAsyncHandler(
	pub events.IngestRawPublisher,
	tracker *IngestTracker,
	verifier *auth.JWTVerifier,
	appender TesseraAppender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// 1. Verify JWT
		token := extractBearerToken(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := verifier.Verify(ctx, token)
		if err != nil {
			http.Error(w, fmt.Sprintf("JWT verification failed: %v", err), http.StatusForbidden)
			return
		}

		// 2. Read YAML body
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		// 3. Append to Tessera
		logIndex, err := appender.Add(ctx, body)
		if err != nil {
			http.Error(w, "evidence log unavailable", http.StatusServiceUnavailable)
			return
		}

		// 4. Build publisher identity
		identity := events.PublisherIdentity{
			Sub:      claims.Sub,
			Issuer:   claims.Iss,
			Type:     inferPublisherType(claims.Sub),
			Verified: true,
		}

		// 5. Publish to NATS
		jobID := uuid.New().String()
		tracker.Create(jobID)
		err = pub.PublishIngestRaw(ctx, events.IngestEvent{
			JobID:             jobID,
			LogIndex:          logIndex,
			YAML:              body,
			PublisherIdentity: identity,
		})
		if err != nil {
			// Tessera succeeded but NATS failed - still return 202
			// Background job will recover by scanning Tessera
			httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
				"log_index": logIndex,
				"job_id":    jobID,
				"status":    "pending",
				"warning":   "async processing delayed",
			})
			return
		}

		// 6. Return 202
		httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
			"log_index": logIndex,
			"job_id":    jobID,
			"status":    "pending",
		})
	}
}

func extractBearerToken(authHeader string) string {
	const prefix = "Bearer "
	if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
		return authHeader[len(prefix):]
	}
	return ""
}

func inferPublisherType(sub string) string {
	// GitHub Actions: "repo:org/repo:ref:refs/heads/main"
	if len(sub) > 5 && sub[:5] == "repo:" {
		return "pipeline"
	}
	// K8s ServiceAccount: "system:serviceaccount:namespace:name"
	if len(sub) > 7 && sub[:7] == "system:" {
		return "service"
	}
	return "unknown"
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/store -v -run TestIngestAsyncHandler`
Expected: PASS (both tests pass)

- [ ] **Step 6: Initialize Tessera client in gateway main**

```go
// cmd/gateway/main.go
package main

import (
	"context"
	"os"
	"time"

	"github.com/complytime/core/internal/auth"
	"github.com/complytime/core/internal/tessera"
	// ... other imports
)

func main() {
	ctx := context.Background()

	// ... existing setup ...

	// Initialize Tessera client
	tesseraPath := os.Getenv("TESSERA_STORAGE_PATH")
	if tesseraPath == "" {
		tesseraPath = "/var/lib/tessera" // default
	}

	tesseraClient, err := tessera.NewClient(ctx, tesseraPath, tessera.Options{
		CheckpointTime: 10 * time.Minute,
		CheckpointSize: 100,
	})
	if err != nil {
		slog.Error("failed to initialize Tessera client", "error", err)
		os.Exit(1)
	}
	defer tesseraClient.Close()

	// Initialize JWT verifier
	allowedIssuers := []string{
		"https://token.actions.githubusercontent.com",
		"https://kubernetes.default.svc",
	}
	jwtVerifier := auth.NewJWTVerifier(allowedIssuers)

	// Create stores
	stores := store.Stores{
		// ... existing stores ...
		TesseraAppender: tesseraClient,
	}

	// ... rest of setup ...
}
```

- [ ] **Step 7: Run integration test (if exists) or manual test**

Run: `go build ./cmd/gateway`
Expected: Build succeeds

- [ ] **Step 8: Commit**

```bash
git add internal/store/ cmd/gateway/main.go
git commit -m "feat: integrate Tessera into gateway ingestion flow

- Refactor IngestAsyncHandler to append evidence to Tessera before NATS
- Add JWT verification before accepting evidence
- Add TesseraAppender to Stores struct
- Initialize Tessera client in gateway main
- Return log_index in 202 response
- Infer publisher type from JWT sub claim

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Witness Service - Foundation

**Files:**
- Create: `cmd/witness/config.go`
- Create: `cmd/witness/state.go`
- Create: `cmd/witness/main.go`

- [ ] **Step 1: Write test for witness config parsing**

```go
// cmd/witness/config_test.go
package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	yamlContent := `
witness:
  name: "test-witness"
  poll_interval: 30s
  verification_timeout: 5m

trusted_publishers:
  - name: github-scanners
    issuer: https://token.actions.githubusercontent.com
    sub: "repo:complytime/*"
    allowed_types: [EvaluationLog, EnforcementLog]
  
  - name: k8s-services
    issuer: https://kubernetes.default.svc
    sub: "system:serviceaccount:complytime:*"
    allowed_types: [EvaluationLog, EnforcementLog, Policy]
`

	tmpfile, err := os.CreateTemp("", "witness-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpfile.Close()

	// Load config
	config, err := LoadConfig(tmpfile.Name())
	require.NoError(t, err)

	// Verify witness settings
	assert.Equal(t, "test-witness", config.Witness.Name)
	assert.Equal(t, 30*time.Second, config.Witness.PollInterval)
	assert.Equal(t, 5*time.Minute, config.Witness.VerificationTimeout)

	// Verify publishers
	require.Len(t, config.TrustedPublishers, 2)
	assert.Equal(t, "github-scanners", config.TrustedPublishers[0].Name)
	assert.Equal(t, "https://token.actions.githubusercontent.com", config.TrustedPublishers[0].Issuer)
	assert.Equal(t, "repo:complytime/*", config.TrustedPublishers[0].Sub)
	assert.Contains(t, config.TrustedPublishers[0].AllowedTypes, "EvaluationLog")
}

func TestLoadConfig_InvalidPath(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/witness -v -run TestLoadConfig`
Expected: FAIL with "undefined: LoadConfig"

- [ ] **Step 3: Implement config loading**

```go
// cmd/witness/config.go
package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Witness           WitnessConfig       `yaml:"witness"`
	TrustedPublishers []TrustedPublisher  `yaml:"trusted_publishers"`
}

type WitnessConfig struct {
	Name                string        `yaml:"name"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	VerificationTimeout time.Duration `yaml:"verification_timeout"`
}

type TrustedPublisher struct {
	Name         string   `yaml:"name"`
	Issuer       string   `yaml:"issuer"`
	Sub          string   `yaml:"sub"`           // Glob pattern (e.g., "repo:org/*")
	AllowedTypes []string `yaml:"allowed_types"` // [EvaluationLog, EnforcementLog, Policy, AuditLog]
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	return &config, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/witness -v -run TestLoadConfig`
Expected: PASS (both tests pass)

- [ ] **Step 5: Write test for witness state persistence**

```go
// cmd/witness/state_test.go
package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState_SaveAndLoad(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "witness-state-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Create state
	original := &State{
		LastVerifiedIndex:  12345,
		LastCheckpointHash: "sha256:abc123def456",
		UpdatedAt:          time.Now().UTC().Truncate(time.Second),
	}

	// Save
	err = SaveState(tmpfile.Name(), original)
	require.NoError(t, err)

	// Load
	loaded, err := LoadState(tmpfile.Name())
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.LastVerifiedIndex, loaded.LastVerifiedIndex)
	assert.Equal(t, original.LastCheckpointHash, loaded.LastCheckpointHash)
	assert.Equal(t, original.UpdatedAt.Unix(), loaded.UpdatedAt.Unix())
}

func TestState_LoadNonexistent_ReturnsZeroState(t *testing.T) {
	state, err := LoadState("/nonexistent/state.json")
	require.NoError(t, err)
	assert.Equal(t, uint64(0), state.LastVerifiedIndex)
	assert.Empty(t, state.LastCheckpointHash)
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./cmd/witness -v -run TestState`
Expected: FAIL with "undefined: SaveState"

- [ ] **Step 7: Implement state persistence**

```go
// cmd/witness/state.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type State struct {
	LastVerifiedIndex  uint64    `json:"last_verified_index"`
	LastCheckpointHash string    `json:"last_checkpoint_hash"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func SaveState(path string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}

	return nil
}

func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return zero state if file doesn't exist
			return &State{
				LastVerifiedIndex:  0,
				LastCheckpointHash: "",
				UpdatedAt:          time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./cmd/witness -v -run TestState`
Expected: PASS (both tests pass)

- [ ] **Step 9: Write witness main skeleton**

```go
// cmd/witness/main.go
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Load configuration
	configPath := os.Getenv("WITNESS_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/witness/config.yaml"
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("witness service starting", "name", config.Witness.Name)

	// Load state
	statePath := os.Getenv("WITNESS_STATE_PATH")
	if statePath == "" {
		statePath = "/var/lib/witness/state.json"
	}

	state, err := LoadState(statePath)
	if err != nil {
		slog.Error("failed to load state", "error", err)
		os.Exit(1)
	}

	slog.Info("loaded witness state", "last_verified_index", state.LastVerifiedIndex)

	// TODO: Initialize Tessera client
	// TODO: Initialize PostgreSQL connection
	// TODO: Start verification loop

	// Wait for shutdown signal
	<-ctx.Done()
	slog.Info("witness service shutting down")

	// Save state
	state.UpdatedAt = time.Now()
	if err := SaveState(statePath, state); err != nil {
		slog.Error("failed to save state", "error", err)
	}
}
```

- [ ] **Step 10: Build witness binary**

Run: `go build -o bin/witness ./cmd/witness`
Expected: Build succeeds

- [ ] **Step 11: Test witness runs**

Run: `./bin/witness`
Expected: Exits with "failed to load config" (no config file - expected)

- [ ] **Step 12: Commit**

```bash
git add cmd/witness/
git commit -m "feat: implement witness service foundation

- Add config loading from YAML with trusted publishers
- Add state persistence (last verified index, checkpoint hash)
- Add main entry point with graceful shutdown
- Add unit tests for config and state

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Witness Service - Verification Logic

**Files:**
- Create: `cmd/witness/verifier.go`
- Create: `cmd/witness/verifier_test.go`
- Modify: `cmd/witness/main.go`

- [ ] **Step 1: Write test for entry verification**

```go
// cmd/witness/verifier_test.go
package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifier_VerifyEntry_AllChecksPass(t *testing.T) {
	// Setup: Mock Tessera (entry exists)
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: test"),
		},
	}

	// Setup: Mock PostgreSQL (entry certified, publisher trusted)
	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       true,
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
	}

	// Setup: Trusted publishers config
	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Name:         "github-scanners",
				Issuer:       "https://token.actions.githubusercontent.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog", "EnforcementLog"},
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	// Verify entry
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "Entry should pass all verification checks")
}

func TestVerifier_VerifyEntry_CertificationFailed(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog"),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       false, // Failed certification
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
	}

	config := &Config{TrustedPublishers: []TrustedPublisher{}}
	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail due to failed certification")
}

func TestVerifier_VerifyEntry_PublisherNotTrusted(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog"),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       true,
				publisherIssuer: "https://untrusted-issuer.example.com",
				submittedBy:     "malicious-actor",
			},
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Issuer: "https://token.actions.githubusercontent.com",
				Sub:    "repo:complytime/*",
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail due to untrusted publisher")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/witness -v -run TestVerifier`
Expected: FAIL with "undefined: NewVerifier"

- [ ] **Step 3: Implement entry verifier**

```go
// cmd/witness/verifier.go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type TesseraReader interface {
	Read(ctx context.Context, index uint64) ([]byte, error)
}

type PostgresQuerier interface {
	QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*EvidenceRow, error)
}

type EvidenceRow struct {
	Certified       bool
	PublisherIssuer string
	SubmittedBy     string
}

type Verifier struct {
	tessera *TesseraReader
	db      PostgresQuerier
	config  *Config
}

func NewVerifier(tessera TesseraReader, db PostgresQuerier, config *Config) *Verifier {
	return &Verifier{
		tessera: tessera,
		db:      db,
		config:  config,
	}
}

func (v *Verifier) VerifyEntry(ctx context.Context, logIndex uint64) bool {
	// 1. Fetch entry from Tessera
	entry, err := v.tessera.Read(ctx, logIndex)
	if err != nil {
		slog.Error("failed to read entry from Tessera", "log_index", logIndex, "error", err)
		return false
	}

	// 2. Parse Gemara artifact type
	artifactType, err := parseGemaraType(entry)
	if err != nil {
		slog.Error("invalid Gemara artifact", "log_index", logIndex, "error", err)
		return false
	}

	// 3. Query PostgreSQL for certification result
	evidenceRow, err := v.db.QueryEvidenceByLogIndex(ctx, logIndex)
	if err != nil {
		slog.Warn("entry not yet in PostgreSQL", "log_index", logIndex, "error", err)
		return false
	}

	// 4. Check certification passed
	if !evidenceRow.Certified {
		slog.Warn("entry failed certification", "log_index", logIndex)
		return false
	}

	// 5. Verify publisher identity
	if !v.isPublisherTrusted(evidenceRow.PublisherIssuer, evidenceRow.SubmittedBy, artifactType) {
		slog.Warn("publisher not trusted",
			"log_index", logIndex,
			"issuer", evidenceRow.PublisherIssuer,
			"sub", evidenceRow.SubmittedBy)
		return false
	}

	return true
}

func (v *Verifier) isPublisherTrusted(issuer, sub, artifactType string) bool {
	for _, pub := range v.config.TrustedPublishers {
		// Check issuer matches
		if pub.Issuer != issuer {
			continue
		}

		// Check sub matches (glob pattern)
		matched, err := filepath.Match(pub.Sub, sub)
		if err != nil || !matched {
			continue
		}

		// Check artifact type allowed
		for _, allowedType := range pub.AllowedTypes {
			if allowedType == artifactType {
				return true
			}
		}
	}

	return false
}

func parseGemaraType(entry []byte) (string, error) {
	var metadata struct {
		Metadata struct {
			Type string `yaml:"type"`
		} `yaml:"metadata"`
	}

	if err := yaml.Unmarshal(entry, &metadata); err != nil {
		return "", fmt.Errorf("parse YAML: %w", err)
	}

	if metadata.Metadata.Type == "" {
		return "", fmt.Errorf("missing metadata.type")
	}

	return metadata.Metadata.Type, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/witness -v -run TestVerifier`
Expected: PASS (all 3 tests pass)

- [ ] **Step 5: Commit**

```bash
git add cmd/witness/verifier.go cmd/witness/verifier_test.go
git commit -m "feat: implement witness entry verification logic

- Verify entry exists in Tessera
- Parse Gemara artifact type
- Check certification status from PostgreSQL
- Verify publisher identity against trusted config
- Use glob pattern matching for publisher sub claim

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Witness Service - Reference Integrity Verification

**Files:**
- Modify: `cmd/witness/verifier.go`
- Modify: `cmd/witness/verifier_test.go`

- [ ] **Step 1: Write test for policy reference verification**

```go
// cmd/witness/verifier_test.go (add new test)
func TestVerifier_VerifyEntry_PolicyReferenceExists(t *testing.T) {
	// Setup: Policy artifact at log_index=0
	policyYAML := `metadata:
  type: Policy
requirements:
  - control-id: CC6.1
    title: Encryption at Rest
`

	// Setup: EvaluationLog references policy at log_index=0
	evaluationYAML := `metadata:
  type: EvaluationLog
  mapping-references:
    - id: soc2-policy
      tessera-log-index: 0
target:
  id: production
results:
  - control-id: CC6.1
    eval-result: pass
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			0:  []byte(policyYAML),
			42: []byte(evaluationYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			0: {
				certified:       true,
				publisherIssuer: "https://kubernetes.default.svc",
				submittedBy:     "system:serviceaccount:complytime:admin",
			},
			42: {
				certified:       true,
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
		witnessedIndices: map[uint64]bool{
			0: true, // Policy is witnessed
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Issuer:       "https://token.actions.githubusercontent.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog"},
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	// Verify entry (should check policy reference)
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "Entry should pass when policy reference exists and is witnessed")
}

func TestVerifier_VerifyEntry_PolicyReferenceNotWitnessed(t *testing.T) {
	policyYAML := `metadata:
  type: Policy
`
	evaluationYAML := `metadata:
  type: EvaluationLog
  mapping-references:
    - id: soc2-policy
      tessera-log-index: 0
target:
  id: production
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			0:  []byte(policyYAML),
			42: []byte(evaluationYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			0:  {certified: true, publisherIssuer: "https://kubernetes.default.svc", submittedBy: "system:serviceaccount:complytime:admin"},
			42: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/scanner:ref:refs/heads/main"},
		},
		witnessedIndices: map[uint64]bool{
			// Policy NOT witnessed
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://token.actions.githubusercontent.com", Sub: "repo:complytime/*", AllowedTypes: []string{"EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail when policy reference is not witnessed")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/witness -v -run TestVerifier_VerifyEntry_PolicyReference`
Expected: FAIL (reference verification not implemented yet)

- [ ] **Step 3: Add reference verification to VerifyEntry**

```go
// cmd/witness/verifier.go (modify VerifyEntry function)

func (v *Verifier) VerifyEntry(ctx context.Context, logIndex uint64) bool {
	// ... existing checks 1-5 ...

	// 6. Verify reference integrity (mapping-references)
	policyRefs, err := extractPolicyReferences(entry)
	if err == nil && len(policyRefs) > 0 {
		for _, policyIndex := range policyRefs {
			if !v.verifyPolicyReference(ctx, policyIndex) {
				slog.Warn("policy reference not found or not witnessed",
					"log_index", logIndex,
					"policy_log_index", policyIndex)
				return false
			}
		}
	}

	// 7. For AuditLog, verify evidence references
	if artifactType == "AuditLog" {
		evidenceRefs, err := extractEvidenceReferences(entry)
		if err == nil && len(evidenceRefs) > 0 {
			for _, evidenceIndex := range evidenceRefs {
				if !v.verifyEvidenceReference(ctx, evidenceIndex) {
					slog.Warn("evidence reference not found or not witnessed",
						"log_index", logIndex,
						"evidence_log_index", evidenceIndex)
					return false
				}
			}

			// 8. Verify target scoping
			if !v.verifyTargetScoping(ctx, entry, evidenceRefs) {
				slog.Warn("AuditLog references evidence from multiple targets", "log_index", logIndex)
				return false
			}
		}
	}

	return true
}

func (v *Verifier) verifyPolicyReference(ctx context.Context, policyIndex uint64) bool {
	// Verify policy exists at claimed log_index
	policyEntry, err := v.tessera.Read(ctx, policyIndex)
	if err != nil {
		return false
	}

	// Verify it's actually a Policy artifact
	artifactType, err := parseGemaraType(policyEntry)
	if err != nil || artifactType != "Policy" {
		return false
	}

	// Verify policy is witnessed
	return v.isIndexWitnessed(ctx, policyIndex)
}

func (v *Verifier) verifyEvidenceReference(ctx context.Context, evidenceIndex uint64) bool {
	// Verify evidence exists
	evidenceEntry, err := v.tessera.Read(ctx, evidenceIndex)
	if err != nil {
		return false
	}

	// Verify it's an EvaluationLog or EnforcementLog
	artifactType, err := parseGemaraType(evidenceEntry)
	if err != nil {
		return false
	}
	if artifactType != "EvaluationLog" && artifactType != "EnforcementLog" {
		return false
	}

	// Verify evidence is witnessed
	return v.isIndexWitnessed(ctx, evidenceIndex)
}

func (v *Verifier) verifyTargetScoping(ctx context.Context, auditLog []byte, evidenceRefs []uint64) bool {
	// Parse target from AuditLog
	auditTarget, err := parseTarget(auditLog)
	if err != nil {
		return false
	}

	// Verify all referenced evidence is for the same target
	for _, evidenceIndex := range evidenceRefs {
		evidenceEntry, err := v.tessera.Read(ctx, evidenceIndex)
		if err != nil {
			return false
		}
		evidenceTarget, err := parseTarget(evidenceEntry)
		if err != nil {
			return false
		}
		if evidenceTarget != auditTarget {
			return false
		}
	}

	return true
}

func (v *Verifier) isIndexWitnessed(ctx context.Context, index uint64) bool {
	// Query witness state: has this index been countersigned?
	// For now, delegate to PostgresQuerier
	return v.db.IsIndexWitnessed(ctx, index)
}

func extractPolicyReferences(entry []byte) ([]uint64, error) {
	var doc struct {
		Metadata struct {
			MappingReferences []struct {
				ID              string `yaml:"id"`
				TesseraLogIndex uint64 `yaml:"tessera-log-index"`
			} `yaml:"mapping-references"`
		} `yaml:"metadata"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return nil, err
	}

	var indices []uint64
	for _, ref := range doc.Metadata.MappingReferences {
		if ref.TesseraLogIndex > 0 {
			indices = append(indices, ref.TesseraLogIndex)
		}
	}

	return indices, nil
}

func extractEvidenceReferences(entry []byte) ([]uint64, error) {
	var doc struct {
		Results []struct {
			Evidence []struct {
				TesseraLogIndex uint64 `yaml:"tessera-log-index"`
			} `yaml:"evidence"`
		} `yaml:"results"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return nil, err
	}

	var indices []uint64
	for _, result := range doc.Results {
		for _, evidence := range result.Evidence {
			if evidence.TesseraLogIndex > 0 {
				indices = append(indices, evidence.TesseraLogIndex)
			}
		}
	}

	return indices, nil
}

func parseTarget(entry []byte) (string, error) {
	var doc struct {
		Target struct {
			ID string `yaml:"id"`
		} `yaml:"target"`
	}

	if err := yaml.Unmarshal(entry, &doc); err != nil {
		return "", err
	}

	return doc.Target.ID, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/witness -v -run TestVerifier_VerifyEntry_PolicyReference`
Expected: PASS (both tests pass)

- [ ] **Step 5: Commit**

```bash
git add cmd/witness/verifier.go cmd/witness/verifier_test.go
git commit -m "feat: add reference integrity verification to witness

- Verify policy references (tessera-log-index) exist and are witnessed
- Verify evidence references in AuditLog exist and are witnessed
- Verify target scoping (AuditLog references evidence for single target)
- Extract mapping-references from Gemara YAML

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: End-to-End Integration Test

**Files:**
- Create: `internal/store/evidence_integration_test.go`
- Create: `testdata/gemara/valid-evaluation-log.yaml`
- Create: `testdata/gemara/valid-policy.yaml`

- [ ] **Step 1: Create test fixtures**

```yaml
# testdata/gemara/valid-policy.yaml
metadata:
  type: Policy
  date: 2026-01-01T00:00:00Z
  mapping-references:
    - id: soc2-type2-2026
      title: "SOC 2 Type 2"
      uri: "https://www.aicpa.org/soc2"

target:
  id: production-environment
  type: system
  description: "Production infrastructure"

requirements:
  - control-id: CC6.1
    title: "Logical Access - Encryption at Rest"
    framework: SOC2-Type2
    description: "The entity implements encryption at rest"
```

```yaml
# testdata/gemara/valid-evaluation-log.yaml
metadata:
  type: EvaluationLog
  date: 2026-05-20T10:30:00Z
  mapping-references:
    - id: soc2-policy
      title: "SOC 2 Type 2"
      tessera-log-index: 0

target:
  id: production-cluster
  type: kubernetes-cluster

results:
  - control-id: CC6.1
    eval-result: pass
    evidence:
      - collected: 2026-05-20T10:30:00Z
        source_registry: ghcr.io/aquasecurity/trivy:latest
        executor: github-actions
        attestation_ref: "https://github.com/complytime/scanner/attestations/abc123"
```

- [ ] **Step 2: Verify test fixtures are valid YAML**

Run: `yq eval testdata/gemara/valid-policy.yaml`
Expected: YAML parses successfully

Run: `yq eval testdata/gemara/valid-evaluation-log.yaml`
Expected: YAML parses successfully

- [ ] **Step 3: Write integration test**

```go
// internal/store/evidence_integration_test.go
//go:build integration
// +build integration

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/complytime/core/internal/auth"
	"github.com/complytime/core/internal/events"
	"github.com/complytime/core/internal/store"
	"github.com/complytime/core/internal/tessera"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceIngestion_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Setup: Tessera client (in-memory storage)
	tmpDir := t.TempDir()
	tesseraClient, err := tessera.NewClient(ctx, tmpDir, tessera.DefaultOptions())
	require.NoError(t, err)
	defer tesseraClient.Close()

	// Setup: Mock NATS publisher
	natsPublisher := &mockIngestPublisher{
		published: make([]events.IngestEvent, 0),
	}

	// Setup: Mock JWT verifier (always succeeds)
	jwtVerifier := &mockJWTVerifier{
		claims: &auth.JWTClaims{
			Iss: "https://token.actions.githubusercontent.com",
			Sub: "repo:complytime/scanner:ref:refs/heads/main",
		},
	}

	// Setup: Ingest tracker
	tracker := store.NewIngestTracker()

	// Create handler
	handler := store.IngestAsyncHandler(natsPublisher, tracker, jwtVerifier, tesseraClient)

	// Test: Submit policy artifact
	policyYAML, err := os.ReadFile("../../testdata/gemara/valid-policy.yaml")
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewReader(policyYAML))
	req.Header.Set("Authorization", "Bearer test-jwt-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify: 202 Accepted
	assert.Equal(t, http.StatusAccepted, rec.Code)

	var policyResp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &policyResp)
	assert.Equal(t, float64(0), policyResp["log_index"])
	policyJobID := policyResp["job_id"].(string)

	// Test: Submit evaluation log (references policy)
	evaluationYAML, err := os.ReadFile("../../testdata/gemara/valid-evaluation-log.yaml")
	require.NoError(t, err)

	req = httptest.NewRequest("POST", "/api/ingest", bytes.NewReader(evaluationYAML))
	req.Header.Set("Authorization", "Bearer test-jwt-token")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify: 202 Accepted
	assert.Equal(t, http.StatusAccepted, rec.Code)

	var evalResp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &evalResp)
	assert.Equal(t, float64(1), evalResp["log_index"])

	// Verify: Evidence in Tessera
	policyEntry, err := tesseraClient.Read(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, policyYAML, policyEntry)

	evaluationEntry, err := tesseraClient.Read(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, evaluationYAML, evaluationEntry)

	// Verify: NATS messages published
	require.Len(t, natsPublisher.published, 2)

	// Policy message
	assert.Equal(t, uint64(0), natsPublisher.published[0].LogIndex)
	assert.Equal(t, policyJobID, natsPublisher.published[0].JobID)
	assert.Equal(t, policyYAML, natsPublisher.published[0].YAML)
	assert.Equal(t, "https://token.actions.githubusercontent.com", natsPublisher.published[0].PublisherIdentity.Issuer)
	assert.True(t, natsPublisher.published[0].PublisherIdentity.Verified)

	// Evaluation message
	assert.Equal(t, uint64(1), natsPublisher.published[1].LogIndex)
	assert.Equal(t, evaluationYAML, natsPublisher.published[1].YAML)
}

func TestEvidenceIngestion_TesseraFailure(t *testing.T) {
	ctx := context.Background()

	// Setup: Tessera client that always fails
	failingTessera := &mockFailingTessera{}

	natsPublisher := &mockIngestPublisher{}
	jwtVerifier := &mockJWTVerifier{
		claims: &auth.JWTClaims{
			Iss: "https://token.actions.githubusercontent.com",
			Sub: "repo:complytime/scanner:ref:refs/heads/main",
		},
	}
	tracker := store.NewIngestTracker()

	handler := store.IngestAsyncHandler(natsPublisher, tracker, jwtVerifier, failingTessera)

	// Submit evidence
	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewReader([]byte("evidence")))
	req.Header.Set("Authorization", "Bearer test-jwt-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify: 503 Service Unavailable
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// Verify: NATS message NOT published
	assert.Empty(t, natsPublisher.published)
}

// Mock implementations
type mockIngestPublisher struct {
	published []events.IngestEvent
}

func (m *mockIngestPublisher) PublishIngestRaw(ctx context.Context, evt events.IngestEvent) error {
	m.published = append(m.published, evt)
	return nil
}

type mockJWTVerifier struct {
	claims     *auth.JWTClaims
	shouldFail bool
}

func (m *mockJWTVerifier) Verify(ctx context.Context, token string) (*auth.JWTClaims, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("verification failed")
	}
	return m.claims, nil
}

type mockFailingTessera struct{}

func (m *mockFailingTessera) Add(ctx context.Context, entry []byte) (uint64, error) {
	return 0, fmt.Errorf("tessera storage unavailable")
}
```

- [ ] **Step 4: Run integration test**

Run: `go test ./internal/store -tags=integration -v -run TestEvidenceIngestion`
Expected: PASS (both integration tests pass)

- [ ] **Step 5: Commit**

```bash
git add internal/store/evidence_integration_test.go testdata/gemara/
git commit -m "test: add end-to-end integration test for evidence ingestion

- Test complete flow: JWT auth → Tessera append → NATS publish
- Test policy + evaluation log submission with references
- Test Tessera failure handling (503 response)
- Add Gemara test fixtures (Policy, EvaluationLog)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Deployment Configuration

**Files:**
- Create: `deploy/k8s/witness-deployment.yaml`
- Create: `deploy/k8s/witness-config.yaml`
- Create: `deploy/k8s/tessera-pvc.yaml`

- [ ] **Step 1: Create Tessera PersistentVolumeClaim**

```yaml
# deploy/k8s/tessera-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: tessera-storage
  namespace: complytime
  labels:
    app: tessera
spec:
  accessModes:
    - ReadWriteMany  # Gateway writes, witness reads
  resources:
    requests:
      storage: 100Gi
  storageClassName: standard-rwx  # Cloud-specific (GCP: filestore, AWS: EFS, Azure: AzureFile)
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: witness-state
  namespace: complytime
  labels:
    app: compliance-witness
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: standard
```

- [ ] **Step 2: Verify PVC YAML is valid**

Run: `kubectl apply --dry-run=client -f deploy/k8s/tessera-pvc.yaml`
Expected: "persistentvolumeclaim/tessera-storage created (dry run)"

- [ ] **Step 3: Create witness ConfigMap**

```yaml
# deploy/k8s/witness-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: witness-config
  namespace: complytime
data:
  config.yaml: |
    witness:
      name: "internal-compliance-witness"
      poll_interval: 30s
      verification_timeout: 5m
    
    trusted_publishers:
      - name: github-scanners
        issuer: https://token.actions.githubusercontent.com
        sub: "repo:complytime/*"
        allowed_types: [EvaluationLog, EnforcementLog]
      
      - name: internal-workloads
        issuer: https://kubernetes.default.svc
        sub: "system:serviceaccount:complytime:*"
        allowed_types: [EvaluationLog, EnforcementLog, Policy]
      
      - name: kyverno-enforcer
        issuer: https://kubernetes.default.svc
        sub: "system:serviceaccount:kyverno:*"
        allowed_types: [EnforcementLog]
```

- [ ] **Step 4: Verify ConfigMap YAML is valid**

Run: `kubectl apply --dry-run=client -f deploy/k8s/witness-config.yaml`
Expected: "configmap/witness-config created (dry run)"

- [ ] **Step 5: Create witness Deployment**

```yaml
# deploy/k8s/witness-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-witness
  namespace: complytime
  labels:
    app: compliance-witness
spec:
  replicas: 1
  selector:
    matchLabels:
      app: compliance-witness
  template:
    metadata:
      labels:
        app: compliance-witness
    spec:
      serviceAccountName: compliance-witness
      containers:
      - name: witness
        image: complytime/witness:latest
        env:
          - name: WITNESS_CONFIG_PATH
            value: /etc/witness/config.yaml
          - name: WITNESS_STATE_PATH
            value: /var/lib/witness/state.json
          - name: TESSERA_STORAGE_PATH
            value: /var/lib/tessera
          - name: POSTGRES_URL
            valueFrom:
              secretKeyRef:
                name: postgres-credentials
                key: url
        volumeMounts:
          - name: witness-config
            mountPath: /etc/witness
            readOnly: true
          - name: witness-state
            mountPath: /var/lib/witness
          - name: tessera-storage
            mountPath: /var/lib/tessera
            readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
        - name: witness-config
          configMap:
            name: witness-config
        - name: witness-state
          persistentVolumeClaim:
            claimName: witness-state
        - name: tessera-storage
          persistentVolumeClaim:
            claimName: tessera-storage
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: compliance-witness
  namespace: complytime
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: witness-tessera-reader
  namespace: complytime
rules:
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    resourceNames: ["tessera-storage"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: witness-tessera-reader-binding
  namespace: complytime
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: witness-tessera-reader
subjects:
  - kind: ServiceAccount
    name: compliance-witness
    namespace: complytime
```

- [ ] **Step 6: Verify Deployment YAML is valid**

Run: `kubectl apply --dry-run=client -f deploy/k8s/witness-deployment.yaml`
Expected: "deployment.apps/compliance-witness created (dry run)"

- [ ] **Step 7: Commit**

```bash
git add deploy/k8s/
git commit -m "feat: add Kubernetes deployment manifests for witness service

- Add Tessera PersistentVolumeClaim (100Gi, ReadWriteMany)
- Add witness state PVC (1Gi, ReadWriteOnce)
- Add witness ConfigMap with trusted publishers
- Add witness Deployment with ServiceAccount and RBAC
- Mount Tessera storage read-only for witness

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

Before presenting the plan to the user, verify:

- [ ] **Spec coverage**: All components from the spec are covered (Tessera client, JWT, gateway, witness, migration, NATS schema, integration test, deployment)
- [ ] **No placeholders**: No TBD, TODO, "implement later", "add appropriate error handling", or "similar to Task N" phrases
- [ ] **Type consistency**: IngestEvent.LogIndex is uint64 everywhere, evidence.log_index is BIGINT, JWT claims match across files
- [ ] **File paths**: All paths are exact (internal/tessera/client.go, cmd/witness/main.go, migrations/019_add_log_index.sql)
- [ ] **Complete code**: Every step that modifies code includes the actual code (no "add validation" without showing the code)
- [ ] **Exact commands**: All test commands, build commands, git commands are runnable (go test ./internal/tessera -v)
- [ ] **TDD adherence**: Every task follows write test → run to fail → implement → run to pass → commit

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-23-tessera-evidence-ingestion.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
