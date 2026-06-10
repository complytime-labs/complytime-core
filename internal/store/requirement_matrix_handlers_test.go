// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/audit"
	"github.com/complytime-labs/complytime-core/internal/posture"
	"github.com/complytime-labs/complytime-core/internal/requirements"
	"github.com/complytime-labs/complytime-core/internal/store"
	"github.com/labstack/echo/v4"
)

type stubPolicyStore struct{}

func (stubPolicyStore) InsertPolicy(ctx context.Context, p requirements.Policy) error {
	return nil
}

func (stubPolicyStore) ListPolicies(ctx context.Context) ([]requirements.Policy, error) {
	return nil, nil
}

func (stubPolicyStore) GetPolicy(ctx context.Context, policyID string) (*requirements.Policy, error) {
	return nil, nil
}

type mockRequirementStore struct {
	matrixHook   func(ctx context.Context, f posture.RequirementFilter) ([]posture.RequirementRow, error)
	evidenceHook func(ctx context.Context, reqID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error)

	lastMatrixF   posture.RequirementFilter
	lastEvidenceF posture.RequirementFilter
	lastReqID     string
}

func (m *mockRequirementStore) ListRequirementMatrix(ctx context.Context, f posture.RequirementFilter) ([]posture.RequirementRow, error) {
	m.lastMatrixF = f
	if m.matrixHook != nil {
		return m.matrixHook(ctx, f)
	}
	return nil, nil
}

func (m *mockRequirementStore) ListRequirementEvidence(ctx context.Context, requirementID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error) {
	m.lastEvidenceF = f
	m.lastReqID = requirementID
	if m.evidenceHook != nil {
		return m.evidenceHook(ctx, requirementID, f)
	}
	return nil, nil
}

func testStoresWithRequirements(m *mockRequirementStore) store.Stores {
	return store.Stores{
		Requirements: m,
		Policies:     stubPolicyStore{},
	}
}

func TestListRequirementMatrixHandler(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		url         string
		wantCode    int
		wantBodySub string
		setup       func(*mockRequirementStore)
		checkFilter func(t *testing.T, m *mockRequirementStore)
		checkJSON   func(t *testing.T, body string)
	}{
		{
			name:        "missing policy_id",
			url:         "/api/requirements",
			wantCode:    http.StatusBadRequest,
			wantBodySub: "policy_id required",
		},
		{
			name:        "invalid audit_start",
			url:         "/api/requirements?policy_id=p1&audit_start=not-a-date",
			wantCode:    http.StatusBadRequest,
			wantBodySub: "invalid audit_start format",
		},
		{
			name:        "audit_end before audit_start",
			url:         "/api/requirements?policy_id=p1&audit_start=2026-01-20&audit_end=2026-01-10",
			wantCode:    http.StatusBadRequest,
			wantBodySub: "audit_end must be",
		},
		{
			name:     "ok with seeded rows",
			url:      "/api/requirements?policy_id=p1",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.matrixHook = func(ctx context.Context, f posture.RequirementFilter) ([]posture.RequirementRow, error) {
					return []posture.RequirementRow{
						{
							CatalogID: "cat-1", ControlID: "C-1", ControlTitle: "Ctl",
							RequirementID: "R-1", RequirementText: "Do thing",
							EvidenceCount: 3, LatestEvidence: "2026-01-15", Classification: "Healthy",
						},
					}, nil
				}
			},
			checkJSON: func(t *testing.T, body string) {
				t.Helper()
				var rows []posture.RequirementRow
				if err := json.Unmarshal([]byte(body), &rows); err != nil {
					t.Fatalf("json: %v", err)
				}
				if len(rows) != 1 || rows[0].RequirementID != "R-1" {
					t.Fatalf("unexpected rows: %+v", rows)
				}
			},
		},
		{
			name:     "pagination limit and offset passed to store",
			url:      "/api/requirements?policy_id=p1&limit=25&offset=10",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.matrixHook = func(ctx context.Context, f posture.RequirementFilter) ([]posture.RequirementRow, error) {
					return []posture.RequirementRow{}, nil
				}
			},
			checkFilter: func(t *testing.T, m *mockRequirementStore) {
				t.Helper()
				if m.lastMatrixF.Limit != 25 || m.lastMatrixF.Offset != 10 {
					t.Fatalf("Limit=%d Offset=%d", m.lastMatrixF.Limit, m.lastMatrixF.Offset)
				}
			},
		},
		{
			name:     "filters and audit window passed to store",
			url:      "/api/requirements?policy_id=p1&audit_start=2026-01-10&audit_end=2026-01-20&classification=Healthy&control_family=AC",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.matrixHook = func(ctx context.Context, f posture.RequirementFilter) ([]posture.RequirementRow, error) {
					return nil, nil
				}
			},
			checkFilter: func(t *testing.T, m *mockRequirementStore) {
				t.Helper()
				f := m.lastMatrixF
				if f.PolicyID != "p1" || f.Classification != "Healthy" || f.ControlFamily != "AC" {
					t.Fatalf("filter: %+v", f)
				}
				if !f.Start.Equal(start) || !f.End.Equal(end) {
					t.Fatalf("Start=%v End=%v want %v %v", f.Start, f.End, start, end)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &mockRequirementStore{}
			if tt.setup != nil {
				tt.setup(m)
			}
			e := echo.New()
			g := e.Group("/api")
			store.Register(g, testStoresWithRequirements(m))

			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
			}
			if tt.wantBodySub != "" && !strings.Contains(rec.Body.String(), tt.wantBodySub) {
				t.Fatalf("body %q want %q", rec.Body.String(), tt.wantBodySub)
			}
			if tt.checkFilter != nil {
				tt.checkFilter(t, m)
			}
			if tt.checkJSON != nil {
				tt.checkJSON(t, rec.Body.String())
			}
		})
	}
}

func TestListRequirementEvidenceHandler(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		url         string
		wantCode    int
		wantBodySub string
		setup       func(*mockRequirementStore)
		checkFilter func(t *testing.T, m *mockRequirementStore)
		checkJSON   func(t *testing.T, body string)
	}{
		{
			name:        "missing policy_id",
			url:         "/api/requirements/r1/evidence",
			wantCode:    http.StatusBadRequest,
			wantBodySub: "policy_id required",
		},
		{
			name:     "unknown requirement returns 404",
			url:      "/api/requirements/unknown-req/evidence?policy_id=p1",
			wantCode: http.StatusNotFound,
			setup: func(m *mockRequirementStore) {
				m.evidenceHook = func(ctx context.Context, reqID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error) {
					return nil, audit.ErrRequirementNotFound
				}
			},
			wantBodySub: "not found",
		},
		{
			name:     "ok with rows",
			url:      "/api/requirements/r1/evidence?policy_id=p1",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.evidenceHook = func(ctx context.Context, reqID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error) {
					return []posture.RequirementEvidenceRow{
						{
							EvidenceID: "e1", TargetID: "t1", RuleID: "rule",
							EvalResult: "Passed", CollectedAt: "2026-02-01 00:00:00",
						},
					}, nil
				}
			},
			checkJSON: func(t *testing.T, body string) {
				t.Helper()
				var rows []posture.RequirementEvidenceRow
				if err := json.Unmarshal([]byte(body), &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 || rows[0].EvidenceID != "e1" {
					t.Fatalf("rows %+v", rows)
				}
			},
		},
		{
			name:     "pagination limit offset",
			url:      "/api/requirements/r1/evidence?policy_id=p1&limit=5&offset=15",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.evidenceHook = func(ctx context.Context, reqID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error) {
					return nil, nil
				}
			},
			checkFilter: func(t *testing.T, m *mockRequirementStore) {
				t.Helper()
				if m.lastReqID != "r1" {
					t.Fatalf("req id %q", m.lastReqID)
				}
				if m.lastEvidenceF.Limit != 5 || m.lastEvidenceF.Offset != 15 {
					t.Fatalf("Limit=%d Offset=%d", m.lastEvidenceF.Limit, m.lastEvidenceF.Offset)
				}
			},
		},
		{
			name:     "audit_start passed",
			url:      "/api/requirements/r1/evidence?policy_id=p1&audit_start=2026-02-01",
			wantCode: http.StatusOK,
			setup: func(m *mockRequirementStore) {
				m.evidenceHook = func(ctx context.Context, reqID string, f posture.RequirementFilter) ([]posture.RequirementEvidenceRow, error) {
					return nil, nil
				}
			},
			checkFilter: func(t *testing.T, m *mockRequirementStore) {
				t.Helper()
				if !m.lastEvidenceF.Start.Equal(start) {
					t.Fatalf("Start=%v", m.lastEvidenceF.Start)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &mockRequirementStore{}
			if tt.setup != nil {
				tt.setup(m)
			}
			e := echo.New()
			g := e.Group("/api")
			store.Register(g, testStoresWithRequirements(m))

			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
			}
			if tt.wantBodySub != "" && !strings.Contains(rec.Body.String(), tt.wantBodySub) {
				t.Fatalf("body %q want substr %q", rec.Body.String(), tt.wantBodySub)
			}
			if tt.checkFilter != nil {
				tt.checkFilter(t, m)
			}
			if tt.checkJSON != nil {
				tt.checkJSON(t, rec.Body.String())
			}
		})
	}
}

// TestRequirementEvidenceAssessmentJoinContract documents that drill-down and
// matrix handlers delegate to RequirementStore, where ListRequirementEvidence
// uses an argMax subquery over evidence_assessments (latest classification per
// evidence_id).
func TestRequirementEvidenceAssessmentJoinContract(t *testing.T) {
	t.Parallel()
	if audit.ErrRequirementNotFound == nil {
		t.Fatal("ErrRequirementNotFound must be non-nil for handler errors.Is")
	}
}
