package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

type fakeTargetStore struct {
	targets []requirements.TargetRow
}

func (f *fakeTargetStore) InsertTarget(_ context.Context, t requirements.TargetRow) error {
	f.targets = append(f.targets, t)
	return nil
}

func (f *fakeTargetStore) GetLatestTarget(_ context.Context, targetID string, asOf time.Time) (*requirements.TargetRow, error) {
	for i := len(f.targets) - 1; i >= 0; i-- {
		t := f.targets[i]
		if t.TargetID == targetID && !t.RegisteredAt.After(asOf) {
			return &t, nil
		}
	}
	return nil, nil
}

func (f *fakeTargetStore) ListTargets(_ context.Context) ([]requirements.TargetRow, error) {
	return f.targets, nil
}

type fakePolicyDimensionStore struct {
	policies []requirements.PolicyWithDimensions
}

func (f *fakePolicyDimensionStore) QueryPoliciesByDimensions(_ context.Context, dims requirements.DimensionQuery) ([]requirements.PolicyWithDimensions, error) {
	var result []requirements.PolicyWithDimensions
	for _, p := range f.policies {
		if arraysOverlap(p.Technologies, dims.Technologies) ||
			arraysOverlap(p.Geopolitical, dims.Geopolitical) ||
			arraysOverlap(p.Sensitivity, dims.Sensitivity) {
			if dims.Timestamp.IsZero() ||
				(!p.EvaluationStart.IsZero() && !dims.Timestamp.Before(p.EvaluationStart) &&
					!p.EvaluationEnd.IsZero() && !dims.Timestamp.After(p.EvaluationEnd)) {
				result = append(result, p)
			}
		}
	}
	return result, nil
}

func TestPolicyQueryHandler_MatchesDimensions(t *testing.T) {
	ts := &fakeTargetStore{
		targets: []requirements.TargetRow{
			{
				TargetID:     "prod-cluster",
				TargetName:   "Production K8s",
				TargetType:   "kubernetes-cluster",
				Technologies: []string{"kubernetes", "postgresql"},
				Geopolitical: []string{"EU"},
				Sensitivity:  []string{"confidential"},
				RegisteredAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	now := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
	ps := &fakePolicyDimensionStore{
		policies: []requirements.PolicyWithDimensions{
			{
				LogIndex:        42,
				PolicyID:        "infra-baseline",
				Title:           "Infrastructure Baseline",
				Technologies:    []string{"kubernetes"},
				EvaluationStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
				EvaluationEnd:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/policies/discover?target_id=prod-cluster&timestamp="+now.Format(time.RFC3339), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := policyQueryHandler(ts, ps)
	err := handler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp requirements.PolicyQueryResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "prod-cluster", resp.Target.ID)
	require.Len(t, resp.ApplicablePolicies, 1)
	assert.Equal(t, "infra-baseline", resp.ApplicablePolicies[0].PolicyID)
}

func TestPolicyQueryHandler_TargetNotFound(t *testing.T) {
	ts := &fakeTargetStore{targets: []requirements.TargetRow{}}
	ps := &fakePolicyDimensionStore{}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/policies/discover?target_id=unknown&timestamp=2026-05-26T10:00:00Z", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := policyQueryHandler(ts, ps)
	err := handler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPolicyQueryHandler_MissingTargetID(t *testing.T) {
	ts := &fakeTargetStore{}
	ps := &fakePolicyDimensionStore{}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/policies/discover", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := policyQueryHandler(ts, ps)
	err := handler(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestArraysOverlap(t *testing.T) {
	assert.True(t, arraysOverlap([]string{"a", "b"}, []string{"b", "c"}))
	assert.False(t, arraysOverlap([]string{"a", "b"}, []string{"c", "d"}))
	assert.False(t, arraysOverlap([]string{}, []string{"a"}))
	assert.False(t, arraysOverlap(nil, nil))
}
