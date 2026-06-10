// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"context"
	"fmt"
	"time"
)

const schemaVersion = "1.0.0"

var validEvalResults = map[string]bool{
	"Not Run": true, "Passed": true, "Failed": true,
	"Needs Review": true, "Not Applicable": true, "Unknown": true,
}

var validComplianceStatuses = map[string]bool{
	"Compliant": true, "Non-Compliant": true, "Exempt": true,
	"Not Applicable": true, "Unknown": true,
}

// SchemaCertifier validates that required metadata fields are present,
// enum values are within their defined sets, and timestamps are sane.
type SchemaCertifier struct{}

func (c *SchemaCertifier) Name() string    { return "schema" }
func (c *SchemaCertifier) Version() string { return schemaVersion }

func (c *SchemaCertifier) Certify(_ context.Context, row EvidenceRow) CertResult {
	result := CertResult{Certifier: c.Name(), Version: c.Version()}

	if row.EvidenceID == "" {
		result.Verdict = VerdictFail
		result.Reason = "evidence_id is missing"
		return result
	}
	if row.TargetID == "" {
		result.Verdict = VerdictFail
		result.Reason = "target_id is missing"
		return result
	}
	if row.RuleID == "" {
		result.Verdict = VerdictFail
		result.Reason = "rule_id is missing"
		return result
	}
	if row.EvalResult == "" {
		result.Verdict = VerdictFail
		result.Reason = "eval_result is missing"
		return result
	}
	if !validEvalResults[row.EvalResult] {
		result.Verdict = VerdictFail
		result.Reason = fmt.Sprintf(
			"eval_result %q is not a valid enum value", row.EvalResult,
		)
		return result
	}
	if row.ComplianceStatus != "" && !validComplianceStatuses[row.ComplianceStatus] {
		result.Verdict = VerdictFail
		result.Reason = fmt.Sprintf(
			"compliance_status %q is not a valid enum value",
			row.ComplianceStatus,
		)
		return result
	}
	if row.CollectedAt.IsZero() {
		result.Verdict = VerdictFail
		result.Reason = "collected_at is missing"
		return result
	}
	if time.Until(row.CollectedAt) > 5*time.Minute {
		result.Verdict = VerdictFail
		result.Reason = "collected_at is in the future"
		return result
	}

	result.Verdict = VerdictPass
	result.Reason = "metadata present and valid"
	return result
}
