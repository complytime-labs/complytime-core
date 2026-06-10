// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/evidence"
)

const minimalEvalLog = `metadata:
  type: EvaluationLog
  id: test-eval-001
  gemara-version: "1.0.0"
  description: test
  date: "2026-04-25T12:00:00Z"
  author:
    id: test
    name: Test
    type: Software
  mapping-references:
    - id: test-policy
      title: Policy
      version: "1.0.0"
result: Passed
target:
  id: test-target
  name: Test Target
  type: Software
evaluations:
  - name: Test Control
    result: Passed
    message: ok
    control:
      reference-id: test-policy
      entry-id: C-1
    assessment-logs:
      - requirement:
          reference-id: test-policy
          entry-id: C-1.01
        description: test
        result: Passed
        message: passed
        applicability: []
        steps: []
        start: "2026-04-25T12:00:00Z"
`

const minimalEnfLog = `metadata:
  type: EnforcementLog
  id: test-enf-001
  gemara-version: "1.0.0"
  description: test enforcement
  date: "2026-04-25T12:00:00Z"
  author:
    id: enforcer
    name: Enforcer
    type: Software
  mapping-references:
    - id: test-policy
      title: Policy
      version: "1.0.0"
result: Passed
target:
  id: test-target
  name: Test Target
  type: Software
actions:
  - name: Block unsigned image
    disposition: Enforced
    start: "2026-04-25T12:00:00Z"
    method:
      reference-id: test-policy
      entry-id: C-1
    justification:
      reason: Policy violation
      exceptions: []
      assessments:
        - result: Passed
          requirement:
            reference-id: test-policy
            entry-id: C-1.01
`

type immediateIngestPublisher struct {
	handler bus.IngestMsgHandler
	reader  TesseraReader
}

func (p *immediateIngestPublisher) PublishIngest(ctx context.Context, ref bus.IngestRef) error {
	p.handler(ctx, ref, &mockJetStreamMsg{})
	return nil
}

// mockJetStreamMsg satisfies jetstream.Msg for synchronous test execution.
type mockJetStreamMsg struct{}

func (m *mockJetStreamMsg) Ack() error                                { return nil }
func (m *mockJetStreamMsg) DoubleAck(context.Context) error           { return nil }
func (m *mockJetStreamMsg) Nak() error                                { return nil }
func (m *mockJetStreamMsg) NakWithDelay(time.Duration) error          { return nil }
func (m *mockJetStreamMsg) InProgress() error                         { return nil }
func (m *mockJetStreamMsg) Term() error                               { return nil }
func (m *mockJetStreamMsg) TermWithReason(string) error               { return nil }
func (m *mockJetStreamMsg) Metadata() (*jetstream.MsgMetadata, error) { return nil, nil }
func (m *mockJetStreamMsg) Data() []byte                              { return nil }
func (m *mockJetStreamMsg) Subject() string                           { return "" }
func (m *mockJetStreamMsg) Reply() string                             { return "" }
func (m *mockJetStreamMsg) Headers() nats.Header                      { return nil }

// Mock Tessera appender for tests
type mockTesseraAppender struct {
	nextIndex uint64
	entries   map[uint64][]byte
}

func (m *mockTesseraAppender) Add(ctx context.Context, entry []byte) (uint64, error) {
	if m.entries == nil {
		m.entries = make(map[uint64][]byte)
	}
	idx := m.nextIndex
	m.entries[idx] = entry
	m.nextIndex++
	return idx, nil
}

func (m *mockTesseraAppender) Read(ctx context.Context, index uint64) ([]byte, error) {
	if m.entries == nil {
		return nil, fmt.Errorf("index %d not yet integrated (log size: 0)", index)
	}
	data, ok := m.entries[index]
	if !ok {
		return nil, fmt.Errorf("index %d not yet integrated (log size: %d)", index, m.nextIndex)
	}
	return data, nil
}

// Mock JWT verifier for tests that always succeeds
type mockJWTVerifier struct{}

func (m *mockJWTVerifier) Verify(ctx context.Context, token string) (*auth.JWTClaims, error) {
	return &auth.JWTClaims{
		Iss: "https://token.actions.githubusercontent.com",
		Sub: "repo:complytime/scanner:ref:refs/heads/main",
		Aud: "https://example.com",
		Exp: int64(time.Now().Add(time.Hour).Unix()),
		Iat: int64(time.Now().Unix()),
	}, nil
}

func echoWithSyncIngest(t *testing.T, ev evidence.EvidenceStore) (*echo.Echo, *IngestTracker) {
	t.Helper()
	ctx := context.Background()
	tracker := NewIngestTracker()
	tessera := &mockTesseraAppender{}
	jwt := &mockJWTVerifier{}
	pub := &immediateIngestPublisher{reader: tessera}
	st := Stores{
		Evidence:        ev,
		IngestTracker:   tracker,
		IngestPublisher: pub,
		TesseraAppender: tessera,
		JWTVerifier:     jwt,
	}
	pub.handler = IngestWorker(ctx, st, nil, tracker, tessera)

	e := echo.New()
	g := e.Group("/api")
	Register(g, st)
	return e, tracker
}

func jobIDFrom202(t *testing.T, body []byte) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	jid, _ := resp["job_id"].(string)
	if jid == "" {
		t.Fatalf("missing job_id in response: %s", body)
	}
	return jid
}

func TestContract_POST_api_ingest_EvaluationLog(t *testing.T) {
	t.Parallel()
	fake := &fakeEvidenceStore{}
	e, tracker := echoWithSyncIngest(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(minimalEvalLog))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}

	jid := jobIDFrom202(t, rec.Body.Bytes())
	st := tracker.Get(jid)
	if st == nil || st.Status != "completed" {
		t.Fatalf("job status = %+v", st)
	}
	if len(fake.inserted) != 1 {
		t.Fatalf("expected 1 inserted record, got %d", len(fake.inserted))
	}
	rec0 := fake.inserted[0]
	if rec0.PolicyID != "test-policy" {
		t.Errorf("PolicyID = %q, want %q", rec0.PolicyID, "test-policy")
	}
	if rec0.TargetID != "test-target" {
		t.Errorf("TargetID = %q, want %q", rec0.TargetID, "test-target")
	}
	if rec0.EvalResult != "Passed" {
		t.Errorf("EvalResult = %q, want %q", rec0.EvalResult, "Passed")
	}
}

func TestContract_POST_api_ingest_EnforcementLog(t *testing.T) {
	t.Parallel()
	fake := &fakeEvidenceStore{}
	e, tracker := echoWithSyncIngest(t, fake)

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(minimalEnfLog))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}

	jid := jobIDFrom202(t, rec.Body.Bytes())
	st := tracker.Get(jid)
	if st == nil || st.Status != "completed" || st.ArtifactType != "" {
		t.Fatalf("job status = %+v", st)
	}
	if len(fake.inserted) == 0 {
		t.Fatal("expected at least 1 inserted record")
	}
}

func TestContract_POST_api_ingest_EmptyBody(t *testing.T) {
	t.Parallel()
	e := echo.New()
	g := e.Group("/api")
	Register(g, Stores{
		Evidence:        &fakeEvidenceStore{},
		IngestTracker:   NewIngestTracker(),
		IngestPublisher: &immediateIngestPublisher{},
		TesseraAppender: &mockTesseraAppender{},
		JWTVerifier:     &mockJWTVerifier{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestContract_POST_api_ingest_InvalidYAML(t *testing.T) {
	t.Parallel()
	e, tracker := echoWithSyncIngest(t, &fakeEvidenceStore{})

	body := "not: valid: yaml: ["
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}

	jid := jobIDFrom202(t, rec.Body.Bytes())
	st := tracker.Get(jid)
	if st == nil || st.Status != "failed" {
		t.Fatalf("expected failed job, got %+v", st)
	}
}

func TestContract_POST_api_ingest_UnsupportedArtifactType(t *testing.T) {
	t.Parallel()
	body := "metadata:\n  type: AuditLog\n  id: bad\n  gemara-version: \"1.0.0\"\n"
	e, tracker := echoWithSyncIngest(t, &fakeEvidenceStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}

	jid := jobIDFrom202(t, rec.Body.Bytes())
	st := tracker.Get(jid)
	if st == nil || st.Status != "failed" || !strings.Contains(st.Error, "unsupported artifact") {
		t.Fatalf("expected unsupported failure, got %+v", st)
	}
}

func TestContract_POST_api_ingest_InsertFailure(t *testing.T) {
	t.Parallel()
	e, tracker := echoWithSyncIngest(t, &failingEvidenceStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(minimalEvalLog))
	req.Header.Set("Content-Type", "application/x-yaml")
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}

	jid := jobIDFrom202(t, rec.Body.Bytes())
	st := tracker.Get(jid)
	if st == nil || st.Status != "failed" || !strings.Contains(st.Error, "insert") {
		t.Fatalf("expected insert failure, got %+v", st)
	}
}

func TestContract_POST_api_ingest_MissingAuthorizationHeader(t *testing.T) {
	t.Parallel()
	e := echo.New()
	g := e.Group("/api")
	Register(g, Stores{
		Evidence:        &fakeEvidenceStore{},
		IngestTracker:   NewIngestTracker(),
		IngestPublisher: &immediateIngestPublisher{},
		TesseraAppender: &mockTesseraAppender{},
		JWTVerifier:     &mockJWTVerifier{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(minimalEvalLog))
	req.Header.Set("Content-Type", "application/x-yaml")
	// Deliberately omit Authorization header
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	errors, ok := resp["errors"].([]interface{})
	if !ok || len(errors) == 0 {
		t.Fatalf("expected errors array in response, got %v", resp)
	}
}
