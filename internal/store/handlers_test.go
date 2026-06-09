// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

type fakeEvidenceStore struct {
	inserted []EvidenceRecord
	query    []EvidenceRecord
}

func (f *fakeEvidenceStore) InsertEvidence(ctx context.Context, records []EvidenceRecord) (int, error) {
	f.inserted = append([]EvidenceRecord{}, records...)
	return len(records), nil
}

func (f *fakeEvidenceStore) QueryEvidence(ctx context.Context, filt EvidenceFilter) ([]EvidenceRecord, error) {
	out := make([]EvidenceRecord, len(f.query))
	copy(out, f.query)
	return out, nil
}

type failingEvidenceStore struct{ fakeEvidenceStore }

func (f *failingEvidenceStore) InsertEvidence(_ context.Context, _ []EvidenceRecord) (int, error) {
	return 0, errors.New("db connection lost")
}

func TestQueryEvidenceHandler_SourceRegistryJSON(t *testing.T) {
	t.Parallel()
	fake := &fakeEvidenceStore{
		query: []EvidenceRecord{
			{
				EvidenceID:     "ev-1",
				PolicyID:       "pol-1",
				TargetID:       "tgt-1",
				ControlID:      "c1",
				RuleID:         "r1",
				EvalResult:     "Passed",
				SourceRegistry: "oci://boundary.registry/ns/repo",
				CollectedAt:    time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	srv := echo.New()
	g := srv.Group("/api")
	Register(g, Stores{Evidence: fake})

	req := httptest.NewRequest(http.MethodGet, "/api/evidence?policy_id=pol-1&limit=10", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len %d", len(got))
	}
	if got[0]["source_registry"] != "oci://boundary.registry/ns/repo" {
		t.Fatalf("source_registry field: %v", got[0]["source_registry"])
	}
}
