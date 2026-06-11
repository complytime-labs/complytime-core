// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"

	"github.com/complytime-labs/complytime-core/internal/blob"
)

// Allowed values for evidence columns (aligned with Gemara enum definitions).
var (
	validEvalResults = map[string]struct{}{
		"Not Run": {}, "Passed": {}, "Failed": {}, "Needs Review": {},
		"Not Applicable": {}, "Unknown": {},
	}
	validComplianceStatus = map[string]struct{}{
		"Compliant": {}, "Non-Compliant": {}, "Exempt": {},
		"Not Applicable": {}, "Unknown": {},
	}
	validConfidence = map[string]struct{}{
		"Undetermined": {}, "Low": {}, "Medium": {}, "High": {},
	}
	validRiskLevel = map[string]struct{}{
		"Critical": {}, "High": {}, "Medium": {}, "Low": {}, "Informational": {},
	}
)

// ValidateEvidenceRecordEnums checks enum fields on an EvidenceRecord.
func ValidateEvidenceRecordEnums(rec EvidenceRecord, row int) []string {
	var out []string
	prefix := fmt.Sprintf("row %d: ", row)
	if rec.EvalResult != "" {
		if _, ok := validEvalResults[rec.EvalResult]; !ok {
			out = append(out, prefix+fmt.Sprintf("invalid eval_result %q", rec.EvalResult))
		}
	}
	if rec.ComplianceStatus != "" {
		if _, ok := validComplianceStatus[rec.ComplianceStatus]; !ok {
			out = append(out, prefix+fmt.Sprintf("invalid compliance_status %q", rec.ComplianceStatus))
		}
	}
	if rec.Confidence != "" {
		if _, ok := validConfidence[rec.Confidence]; !ok {
			out = append(out, prefix+fmt.Sprintf("invalid confidence %q", rec.Confidence))
		}
	}
	if rec.RiskLevel != "" {
		if _, ok := validRiskLevel[rec.RiskLevel]; !ok {
			out = append(out, prefix+fmt.Sprintf("invalid risk_level %q", rec.RiskLevel))
		}
	}
	if rec.BlobRef != "" {
		if err := blob.ValidateBlobRef(rec.BlobRef); err != nil {
			out = append(out, prefix+"invalid blob_ref: "+err.Error())
		}
	}
	return out
}
