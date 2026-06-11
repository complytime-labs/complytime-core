// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/blob"
	"github.com/complytime-labs/complytime-core/internal/evidence"
)

func TestValidateEvidenceRecordEnums_TableDriven(t *testing.T) {
	t.Parallel()
	base := evidence.EvidenceRecord{
		EvalResult:       "Passed",
		ComplianceStatus: "Compliant",
		Confidence:       "Medium",
		RiskLevel:        "Low",
	}
	t.Run("valid base", func(t *testing.T) {
		t.Parallel()
		if err := blob.ValidateBlobRef("s3://mybucket/some/key"); err != nil {
			t.Fatal(err)
		}
		if got := validateEvidenceRecordEnums(base, 0); len(got) > 0 {
			t.Fatal(got)
		}
	})
	tests := []struct {
		name   string
		mutate func(*evidence.EvidenceRecord)
		substr string
	}{
		{
			name: "bad eval_result",
			mutate: func(r *evidence.EvidenceRecord) {
				r.EvalResult = "Bogus"
			},
			substr: "invalid eval_result",
		},
		{
			name: "bad compliance_status",
			mutate: func(r *evidence.EvidenceRecord) {
				r.ComplianceStatus = "Partial"
			},
			substr: "invalid compliance_status",
		},
		{
			name: "bad confidence",
			mutate: func(r *evidence.EvidenceRecord) {
				r.Confidence = "SuperHigh"
			},
			substr: "invalid confidence",
		},
		{
			name: "bad risk_level",
			mutate: func(r *evidence.EvidenceRecord) {
				r.RiskLevel = "Extreme"
			},
			substr: "invalid risk_level",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := base
			tt.mutate(&r)
			got := validateEvidenceRecordEnums(r, 2)
			if len(got) != 1 {
				t.Fatalf("got %v", got)
			}
			if !strings.Contains(got[0], tt.substr) {
				t.Fatalf("got %q want substring %q", got[0], tt.substr)
			}
		})
	}
}

func TestValidateBlobRef_Format(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{
		"",
		"http://bucket/key",
		"s3://onlybucket",
		"s3://",
	} {
		if err := blob.ValidateBlobRef(ref); err == nil {
			t.Fatalf("expected error for %q", ref)
		}
	}
	if err := blob.ValidateBlobRef("s3://my-bucket/path/to/object"); err != nil {
		t.Fatal(err)
	}
}
