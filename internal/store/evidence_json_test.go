// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/evidence"
)

func TestEvidenceRecordJSON_MinimalLegacy(t *testing.T) {
	t.Parallel()
	payload := []byte(`[{
		"policy_id": "pol-legacy",
		"target_id": "tgt-1",
		"control_id": "ctl-1",
		"rule_id": "rule-1",
		"eval_result": "Passed",
		"collected_at": "2026-03-01T08:30:00Z"
	}]`)
	var got []evidence.EvidenceRecord
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len %d", len(got))
	}
	r := got[0]
	if r.PolicyID != "pol-legacy" || r.TargetID != "tgt-1" || r.ControlID != "ctl-1" || r.RuleID != "rule-1" {
		t.Fatalf("identifiers: %+v", r)
	}
	if r.EvalResult != "Passed" {
		t.Fatalf("eval_result %q", r.EvalResult)
	}
	if !r.CollectedAt.Equal(time.Date(2026, 3, 1, 8, 30, 0, 0, time.UTC)) {
		t.Fatalf("collected_at %v", r.CollectedAt)
	}
	if r.RequirementID != "" || r.BlobRef != "" || r.EngineName != "" {
		t.Fatalf("expected empty optional fields, got req=%q blob=%q engine=%q", r.RequirementID, r.BlobRef, r.EngineName)
	}
}

func TestEvidenceRecordJSON_FullSemconvShape(t *testing.T) {
	t.Parallel()
	payload := []byte(`[{
		"evidence_id": "ev-sem-1",
		"policy_id": "pol-full",
		"target_id": "tgt-full",
		"target_name": "prod-cluster",
		"target_type": "k8s",
		"target_env": "production",
		"engine_name": "Kyverno",
		"engine_version": "1.11.0",
		"rule_id": "rule-full",
		"rule_name": "require-labels",
		"rule_uri": "https://example/pol#rule",
		"eval_result": "Failed",
		"eval_message": "missing label",
		"control_id": "ctl-full",
		"control_catalog_id": "cat-1",
		"control_category": "access",
		"control_applicability": ["workloads"],
		"requirement_id": "req-42",
		"plan_id": "plan-q1",
		"confidence": "High",
		"steps_executed": 3,
		"compliance_status": "Non-Compliant",
		"risk_level": "High",
		"frameworks": ["SOC2"],
		"requirements": ["CC6.1"],
		"remediation_action": "Remediate",
		"remediation_status": "Fail",
		"remediation_desc": "add labels",
		"exception_id": "ex-1",
		"exception_active": true,
		"attestation_ref": "sha256:abcd",
		"source_registry": "oci://registry.example/ns",
		"blob_ref": "s3://bucket/obj/key",
		"owner": "team-a",
		"collected_at": "2026-04-25T15:00:00Z"
	}]`)
	var got []evidence.EvidenceRecord
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len %d", len(got))
	}
	r := got[0]
	if r.RequirementID != "req-42" || r.PlanID != "plan-q1" || r.Confidence != "High" {
		t.Fatalf("assessment fields: %+v", r)
	}
	if r.ComplianceStatus != "Non-Compliant" {
		t.Fatalf("status fields: %+v", r)
	}
	if r.BlobRef != "s3://bucket/obj/key" || r.AttestationRef != "sha256:abcd" {
		t.Fatalf("refs: blob=%q att=%q", r.BlobRef, r.AttestationRef)
	}
	if len(r.Frameworks) != 1 || r.Frameworks[0] != "SOC2" {
		t.Fatalf("frameworks %v", r.Frameworks)
	}
	if r.ExceptionActive == nil || !*r.ExceptionActive {
		t.Fatal("exception_active")
	}
	if r.StepsExecuted != 3 {
		t.Fatalf("steps %d", r.StepsExecuted)
	}
}
