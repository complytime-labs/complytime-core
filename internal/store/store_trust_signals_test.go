// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/certifier"
)

func TestIntegration_InsertAndQueryTrustSignals(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	signals := []TrustSignalRow{
		{EvidenceID: "ev-trust-1", Layer: "identity", CheckName: "publisher_auth", Result: certifier.ResultPass, Reason: "Valid JWT signature"},
		{EvidenceID: "ev-trust-1", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "Evidence matches schema"},
		{EvidenceID: "ev-trust-1", Layer: "attestation", CheckName: "provenance", Result: certifier.ResultFail, Reason: "Missing provenance attestation"},
	}

	err := st.InsertTrustSignals(ctx, signals)
	if err != nil {
		t.Fatalf("InsertTrustSignals: %v", err)
	}

	got, err := st.QueryTrustSignals(ctx, "ev-trust-1")
	if err != nil {
		t.Fatalf("QueryTrustSignals: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 signals, got %d", len(got))
	}

	byCheck := make(map[string]TrustSignalRow)
	for _, r := range got {
		byCheck[r.CheckName] = r
	}

	if r, ok := byCheck["publisher_auth"]; !ok || r.Result != certifier.ResultPass {
		t.Errorf("publisher_auth: got %+v, want pass", byCheck["publisher_auth"])
	}
	if r, ok := byCheck["schema"]; !ok || r.Result != certifier.ResultPass {
		t.Errorf("schema: got %+v, want pass", byCheck["schema"])
	}
	if r, ok := byCheck["provenance"]; !ok || r.Result != certifier.ResultFail {
		t.Errorf("provenance: got %+v, want fail", byCheck["provenance"])
	}
}

func TestIntegration_InsertTrustSignals_Upsert(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	original := []TrustSignalRow{
		{EvidenceID: "ev-upsert", Layer: "quality", CheckName: "schema", Result: certifier.ResultFail, Reason: "Validation failed"},
	}
	err := st.InsertTrustSignals(ctx, original)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}

	updated := []TrustSignalRow{
		{EvidenceID: "ev-upsert", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "Validation passed"},
	}
	err = st.InsertTrustSignals(ctx, updated)
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}

	got, err := st.QueryTrustSignals(ctx, "ev-upsert")
	if err != nil {
		t.Fatalf("QueryTrustSignals: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 signal after upsert, got %d", len(got))
	}
	if got[0].Result != certifier.ResultPass {
		t.Errorf("expected upserted result pass, got %q", got[0].Result)
	}
	if got[0].Reason != "Validation passed" {
		t.Errorf("expected reason 'Validation passed', got %q", got[0].Reason)
	}
}

func TestIntegration_QueryTrustSignals_Filters(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	signals1 := []TrustSignalRow{
		{EvidenceID: "ev-filter-1", Layer: "identity", CheckName: "publisher_auth", Result: certifier.ResultPass, Reason: "OK"},
		{EvidenceID: "ev-filter-1", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "OK"},
	}
	signals2 := []TrustSignalRow{
		{EvidenceID: "ev-filter-2", Layer: "identity", CheckName: "publisher_auth", Result: certifier.ResultFail, Reason: "Invalid"},
		{EvidenceID: "ev-filter-2", Layer: "attestation", CheckName: "provenance", Result: certifier.ResultSkip, Reason: "N/A"},
	}

	if err := st.InsertTrustSignals(ctx, signals1); err != nil {
		t.Fatalf("insert signals1: %v", err)
	}
	if err := st.InsertTrustSignals(ctx, signals2); err != nil {
		t.Fatalf("insert signals2: %v", err)
	}

	got, err := st.QueryTrustSignals(ctx, "ev-filter-1")
	if err != nil {
		t.Fatalf("QueryTrustSignals ev-filter-1: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 signals for ev-filter-1, got %d", len(got))
	}

	got, err = st.QueryTrustSignals(ctx, "ev-filter-2")
	if err != nil {
		t.Fatalf("QueryTrustSignals ev-filter-2: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 signals for ev-filter-2, got %d", len(got))
	}
}

func TestIntegration_AggregateCertified(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	allPass := []TrustSignalRow{
		{EvidenceID: "ev-all-pass", Layer: "identity", CheckName: "publisher_auth", Result: certifier.ResultPass, Reason: "OK"},
		{EvidenceID: "ev-all-pass", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "OK"},
		{EvidenceID: "ev-all-pass", Layer: "attestation", CheckName: "provenance", Result: certifier.ResultPass, Reason: "OK"},
	}
	if err := st.InsertTrustSignals(ctx, allPass); err != nil {
		t.Fatalf("insert all pass: %v", err)
	}

	certified := st.AggregateCertified(ctx, "ev-all-pass")
	if !certified {
		t.Errorf("expected certified=true for all pass signals")
	}

	oneFail := []TrustSignalRow{
		{EvidenceID: "ev-one-fail", Layer: "identity", CheckName: "publisher_auth", Result: certifier.ResultPass, Reason: "OK"},
		{EvidenceID: "ev-one-fail", Layer: "quality", CheckName: "schema", Result: certifier.ResultFail, Reason: "Invalid"},
	}
	if err := st.InsertTrustSignals(ctx, oneFail); err != nil {
		t.Fatalf("insert one fail: %v", err)
	}

	certified = st.AggregateCertified(ctx, "ev-one-fail")
	if certified {
		t.Errorf("expected certified=false when one signal fails")
	}

	// Test: skip results are OK (pass + skip = certified)
	passAndSkip := []TrustSignalRow{
		{EvidenceID: "ev-skip-ok", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "Valid"},
		{EvidenceID: "ev-skip-ok", Layer: "attestation", CheckName: "executor", Result: certifier.ResultSkip, Reason: "Not applicable"},
	}
	if err := st.InsertTrustSignals(ctx, passAndSkip); err != nil {
		t.Fatalf("insert pass and skip: %v", err)
	}

	certified = st.AggregateCertified(ctx, "ev-skip-ok")
	if !certified {
		t.Errorf("expected certified=true when all signals are pass or skip")
	}

	// Test: error results fail certification
	passAndError := []TrustSignalRow{
		{EvidenceID: "ev-error-fail", Layer: "quality", CheckName: "schema", Result: certifier.ResultPass, Reason: "Valid"},
		{EvidenceID: "ev-error-fail", Layer: "identity", CheckName: "relevance", Result: certifier.ResultError, Reason: "Check failed"},
	}
	if err := st.InsertTrustSignals(ctx, passAndError); err != nil {
		t.Fatalf("insert pass and error: %v", err)
	}

	certified = st.AggregateCertified(ctx, "ev-error-fail")
	if certified {
		t.Errorf("expected certified=false when any signal has error result")
	}

	certified = st.AggregateCertified(ctx, "ev-no-signals")
	if certified {
		t.Errorf("expected certified=false when no signals exist")
	}
}
