// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	pgstore "github.com/complytime-labs/complytime-core/internal/db"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("POSTGRES_TEST_URL not set — skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := pgstore.New(ctx, pgstore.Config{URL: url})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := client.EnsureSchema(ctx); err != nil {
		client.Close()
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		pool := client.Pool()
		_, _ = pool.Exec(bg, "DELETE FROM trust_signals WHERE evidence_id LIKE 'ev-%'")
		_, _ = pool.Exec(bg, "DELETE FROM evidence_assessments WHERE evidence_id LIKE 'ev-%'")
		_, _ = pool.Exec(bg, "DELETE FROM workbench.jobs")
		_, _ = pool.Exec(bg, "DELETE FROM workbench.programs")
		_, _ = pool.Exec(bg, "DELETE FROM evidence WHERE evidence_id LIKE 'ev-%'")
		_, _ = pool.Exec(bg, "DELETE FROM policies WHERE policy_id LIKE 'pol-%'")
		client.Close()
	})
	return New(client.Pool())
}

func TestIntegration_InsertAndQueryEvidence(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	records := []EvidenceRecord{
		{
			EvidenceID:       "ev-int-1",
			PolicyID:         "pol-int",
			TargetID:         "tgt-1",
			TargetName:       "Web App",
			TargetType:       "Software",
			RuleID:           "r-1",
			ControlID:        "C-1",
			RequirementID:    "C-1.01",
			EvalResult:       "Passed",
			ComplianceStatus: "Compliant",
			EnrichmentStatus: "Success",
			CollectedAt:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			EvidenceID:       "ev-int-2",
			PolicyID:         "pol-int",
			TargetID:         "tgt-1",
			ControlID:        "C-2",
			RequirementID:    "C-2.01",
			RuleID:           "r-2",
			EvalResult:       "Failed",
			ComplianceStatus: "Non-Compliant",
			EnrichmentStatus: "Success",
			CollectedAt:      time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC),
		},
	}

	n, err := st.InsertEvidence(ctx, records)
	if err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}
	if n != 2 {
		t.Fatalf("inserted %d, want 2", n)
	}

	got, err := st.QueryEvidence(ctx, EvidenceFilter{PolicyIDs: []string{"pol-int"}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("queried %d records, want 2", len(got))
	}

	byControl := make(map[string]EvidenceRecord)
	for _, r := range got {
		byControl[r.ControlID] = r
	}
	if r, ok := byControl["C-1"]; !ok || r.EvalResult != "Passed" {
		t.Errorf("C-1: got %+v, want Passed", byControl["C-1"])
	}
	if r, ok := byControl["C-2"]; !ok || r.EvalResult != "Failed" {
		t.Errorf("C-2: got %+v, want Failed", byControl["C-2"])
	}
}

func TestIntegration_InsertEvidence_Upsert(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	original := []EvidenceRecord{{
		EvidenceID:       "ev-upsert",
		PolicyID:         "pol-upsert",
		TargetID:         "tgt-1",
		ControlID:        "C-1",
		RequirementID:    "C-1.01",
		RuleID:           "r-1",
		EvalResult:       "Failed",
		ComplianceStatus: "Non-Compliant",
		EnrichmentStatus: "Success",
		CollectedAt:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}}
	if _, err := st.InsertEvidence(ctx, original); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	updated := []EvidenceRecord{{
		EvidenceID:       "ev-upsert",
		PolicyID:         "pol-upsert",
		TargetID:         "tgt-1",
		ControlID:        "C-1",
		RequirementID:    "C-1.01",
		RuleID:           "r-1",
		EvalResult:       "Passed",
		ComplianceStatus: "Compliant",
		EnrichmentStatus: "Success",
		CollectedAt:      time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC),
	}}
	if _, err := st.InsertEvidence(ctx, updated); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}

	got, err := st.QueryEvidence(ctx, EvidenceFilter{PolicyIDs: []string{"pol-upsert"}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 record after upsert, got %d", len(got))
	}
	if got[0].EvalResult != "Passed" {
		t.Errorf("expected upserted result Passed, got %q", got[0].EvalResult)
	}
}

func TestIntegration_InsertAndListPolicies(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	p := Policy{
		PolicyID:     "pol-test-1",
		Title:        "Test Policy",
		Version:      "1.0.0",
		OCIReference: "oci://example.com/policies/test:1.0.0",
		Content:      "policy: content",
		// Dimensional metadata added by migration 024
		Technologies: []string{},
		Geopolitical: []string{},
		Sensitivity:  []string{},
		Users:        []string{},
		Groups:       []string{},
	}
	if err := st.InsertPolicy(ctx, p); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}

	policies, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	found := false
	for _, pol := range policies {
		if pol.PolicyID == "pol-test-1" {
			found = true
			if pol.Title != "Test Policy" {
				t.Errorf("Title = %q, want %q", pol.Title, "Test Policy")
			}
		}
	}
	if !found {
		t.Fatal("inserted policy not found in ListPolicies")
	}

	got, err := st.GetPolicy(ctx, "pol-test-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.OCIReference != p.OCIReference {
		t.Errorf("OCIReference = %q, want %q", got.OCIReference, p.OCIReference)
	}
}

func TestIntegration_QueryEvidence_Filters(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	records := []EvidenceRecord{
		{
			EvidenceID: "ev-filt-1", PolicyID: "pol-a", TargetID: "tgt-1",
			ControlID: "C-1", RequirementID: "C-1.01", RuleID: "r-1",
			EvalResult: "Passed", ComplianceStatus: "Compliant",
			EnrichmentStatus: "Success",
			CollectedAt:      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			EvidenceID: "ev-filt-2", PolicyID: "pol-b", TargetID: "tgt-2",
			ControlID: "C-2", RequirementID: "C-2.01", RuleID: "r-2",
			EvalResult: "Failed", ComplianceStatus: "Non-Compliant",
			EnrichmentStatus: "Success",
			CollectedAt:      time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC),
		},
	}
	if _, err := st.InsertEvidence(ctx, records); err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}

	got, err := st.QueryEvidence(ctx, EvidenceFilter{PolicyIDs: []string{"pol-a"}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvidence pol-a: %v", err)
	}
	if len(got) != 1 || got[0].EvidenceID != "ev-filt-1" {
		t.Fatalf("expected ev-filt-1 only, got %d records", len(got))
	}

	got, err = st.QueryEvidence(ctx, EvidenceFilter{ControlID: "C-2", Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvidence C-2: %v", err)
	}
	if len(got) != 1 || got[0].EvidenceID != "ev-filt-2" {
		t.Fatalf("expected ev-filt-2 only, got %d records", len(got))
	}
}

func TestIntegration_ListInventory(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pool := st.pool

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 5, 1, 2, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 1, 4, 0, 0, 0, time.UTC)

	records := []EvidenceRecord{
		{
			EvidenceID: "ev-inv-1", PolicyID: "pol-inv-a", TargetID: "tgt-inv",
			TargetType: "cluster", TargetEnv: "prod",
			ControlID: "C-1", RequirementID: "C-1.01", RuleID: "r-1",
			EvalResult: "Passed", ComplianceStatus: "Compliant",
			EnrichmentStatus: "Success", CollectedAt: t0,
		},
		{
			EvidenceID: "ev-inv-2", PolicyID: "pol-inv-a", TargetID: "tgt-inv",
			TargetType: "cluster", TargetEnv: "prod",
			ControlID: "C-2", RequirementID: "C-2.01", RuleID: "r-2",
			EvalResult: "Failed", ComplianceStatus: "Non-Compliant",
			EnrichmentStatus: "Success", CollectedAt: t1,
		},
		{
			EvidenceID: "ev-inv-3", PolicyID: "pol-inv-b", TargetID: "tgt-inv",
			TargetType: "vm", TargetEnv: "staging",
			ControlID: "C-3", RequirementID: "C-3.01", RuleID: "r-3",
			EvalResult: "Passed", ComplianceStatus: "Compliant",
			EnrichmentStatus: "Success", CollectedAt: t2,
		},
		{
			EvidenceID: "ev-inv-4", PolicyID: "pol-inv-c", TargetID: "tgt-other",
			TargetType: "cluster", TargetEnv: "dev",
			ControlID: "C-4", RequirementID: "C-4.01", RuleID: "r-4",
			EvalResult: "Unknown", ComplianceStatus: "Unknown",
			EnrichmentStatus: "Success", CollectedAt: t0,
		},
	}
	if _, err := st.InsertEvidence(ctx, records); err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}

	all, err := st.ListInventory(ctx, InventoryFilter{})
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}
	if len(all) < 2 {
		t.Fatalf("ListInventory: got %d rows, want at least 2", len(all))
	}
	byTarget := make(map[string]*InventoryItem, len(all))
	for i := range all {
		byTarget[all[i].TargetID] = &all[i]
	}
	inv := byTarget["tgt-inv"]
	if inv == nil {
		t.Fatal("tgt-inv not in inventory")
	}
	if byTarget["tgt-other"] == nil {
		t.Fatal("tgt-other not in inventory")
	}
	if inv.PolicyCount != 2 || inv.PassCount != 1 || inv.FailCount != 1 {
		t.Fatalf("tgt-inv counts: policy=%d pass=%d fail=%d want 2,1,1",
			inv.PolicyCount, inv.PassCount, inv.FailCount)
	}
	if !inv.LatestEvidence.Equal(t2) {
		t.Fatalf("LatestEvidence = %v, want %v", inv.LatestEvidence, t2)
	}

	byPolicy, err := st.ListInventory(ctx, InventoryFilter{PolicyID: "pol-inv-a"})
	if err != nil {
		t.Fatalf("ListInventory policy: %v", err)
	}
	if len(byPolicy) != 1 || byPolicy[0].TargetID != "tgt-inv" {
		t.Fatalf("policy filter: %+v", byPolicy)
	}
	if byPolicy[0].FailCount != 1 || byPolicy[0].PassCount != 0 {
		t.Fatalf("pol-inv-a latest should be Failed: %+v", byPolicy[0])
	}

	byEnv, err := st.ListInventory(ctx, InventoryFilter{Environment: "dev"})
	if err != nil {
		t.Fatalf("ListInventory env: %v", err)
	}
	if len(byEnv) != 1 || byEnv[0].TargetID != "tgt-other" {
		t.Fatalf("env filter: %+v", byEnv)
	}

	progID := uuid.New()
	_, err = pool.Exec(ctx,
		`INSERT INTO workbench.programs (id, name, framework, policy_ids) VALUES ($1, 'inv-prog', 'soc2', $2)`,
		progID, []string{"pol-inv-a", "pol-inv-b"})
	if err != nil {
		t.Fatalf("insert program: %v", err)
	}
	byProg, err := st.ListInventory(ctx, InventoryFilter{ProgramID: progID.String()})
	if err != nil {
		t.Fatalf("ListInventory program: %v", err)
	}
	if len(byProg) != 1 || byProg[0].TargetID != "tgt-inv" {
		t.Fatalf("program filter: %+v", byProg)
	}
}
