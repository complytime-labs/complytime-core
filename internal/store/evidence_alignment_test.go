// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/ingest"
)

func sp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func u16(v int) *uint16 {
	if v <= 0 {
		return nil
	}
	u := uint16(v) //nolint:gosec // G115: test value
	return &u
}

// otelShapeFromREST builds the ingest writer row shape from a REST-decoded record.
// Keeps REST and OTel insert paths aligned for the same logical assessment.
func otelShapeFromREST(r evidence.EvidenceRecord) ingest.EvidenceRow {
	active := r.ExceptionActive
	return ingest.EvidenceRow{
		EvidenceID:           r.EvidenceID,
		TargetID:             r.TargetID,
		TargetName:           sp(r.TargetName),
		TargetType:           sp(r.TargetType),
		TargetEnv:            sp(r.TargetEnv),
		EngineName:           sp(r.EngineName),
		EngineVersion:        sp(r.EngineVersion),
		RuleID:               r.RuleID,
		RuleName:             sp(r.RuleName),
		RuleURI:              sp(r.RuleURI),
		EvalResult:           r.EvalResult,
		EvalMessage:          sp(r.EvalMessage),
		PolicyID:             sp(r.PolicyID),
		ControlID:            sp(r.ControlID),
		ControlCatalogID:     sp(r.ControlCatalogID),
		ControlCategory:      sp(r.ControlCategory),
		ControlApplicability: r.ControlApplicability,
		RequirementID:        sp(r.RequirementID),
		PlanID:               sp(r.PlanID),
		Confidence:           sp(r.Confidence),
		StepsExecuted:        u16(r.StepsExecuted),
		ComplianceStatus:     r.ComplianceStatus,
		RiskLevel:            sp(r.RiskLevel),
		Frameworks:           r.Frameworks,
		Requirements:         r.Requirements,
		RemediationAction:    sp(r.RemediationAction),
		RemediationStatus:    sp(r.RemediationStatus),
		RemediationDesc:      sp(r.RemediationDesc),
		ExceptionID:          sp(r.ExceptionID),
		ExceptionActive:      active,
		AttestationRef:       sp(r.AttestationRef),
		SourceRegistry:       sp(r.SourceRegistry),
		BlobRef:              sp(r.BlobRef),
		CollectedAt:          r.CollectedAt,
	}
}

func TestRESTJSON_IngestRowColumnAlignment(t *testing.T) {
	t.Parallel()
	const payload = `{
		"policy_id": "pol-int",
		"target_id": "tgt-int",
		"control_id": "ctl-int",
		"rule_id": "rule-int",
		"eval_result": "Needs Review",
		"requirement_id": "req-int",
		"plan_id": "plan-int",
		"confidence": "Low",
		"compliance_status": "Exempt",
		"source_registry": "oci://reg/ns",
		"blob_ref": "s3://bkt/obj",
		"collected_at": "2026-04-25T18:00:00Z"
	}`
	var r evidence.EvidenceRecord
	if err := json.Unmarshal([]byte(payload), &r); err != nil {
		t.Fatal(err)
	}
	otelFixture := ingest.EvidenceRow{
		PolicyID:         sp("pol-int"),
		TargetID:         "tgt-int",
		ControlID:        sp("ctl-int"),
		RuleID:           "rule-int",
		EvalResult:       "Needs Review",
		RequirementID:    sp("req-int"),
		PlanID:           sp("plan-int"),
		Confidence:       sp("Low"),
		ComplianceStatus: "Exempt",
		SourceRegistry:   sp("oci://reg/ns"),
		BlobRef:          sp("s3://bkt/obj"),
		CollectedAt:      time.Date(2026, 4, 25, 18, 0, 0, 0, time.UTC),
	}
	fromREST := otelShapeFromREST(r)
	if fromREST.EvalResult != otelFixture.EvalResult ||
		fromREST.TargetID != otelFixture.TargetID ||
		fromREST.RuleID != otelFixture.RuleID ||
		deref(fromREST.PolicyID) != deref(otelFixture.PolicyID) ||
		deref(fromREST.ControlID) != deref(otelFixture.ControlID) ||
		deref(fromREST.RequirementID) != deref(otelFixture.RequirementID) ||
		deref(fromREST.PlanID) != deref(otelFixture.PlanID) ||
		deref(fromREST.BlobRef) != deref(otelFixture.BlobRef) ||
		fromREST.ComplianceStatus != otelFixture.ComplianceStatus ||
		!fromREST.CollectedAt.Equal(otelFixture.CollectedAt) {
		t.Fatalf("mismatch\nfrom REST: %+v\nfixture: %+v", fromREST, otelFixture)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
