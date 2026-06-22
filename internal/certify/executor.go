// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"context"
	"fmt"
)

const executorVersion = "1.0.0"

// ExecutorCertifier verifies that the evidence row's engine_name is present
// and matches a registered engine in the service configuration.
type ExecutorCertifier struct {
	KnownEngines map[string]bool
}

func (c *ExecutorCertifier) Name() string    { return "executor" }
func (c *ExecutorCertifier) Version() string { return executorVersion }

func (c *ExecutorCertifier) Certify(_ context.Context, row EvidenceRow) CertResult {
	result := CertResult{Certifier: c.Name(), Version: c.Version()}

	if row.EngineName == "" {
		result.Verdict = VerdictFail
		result.Reason = "engine_name is missing"
		return result
	}

	if len(c.KnownEngines) > 0 && !c.KnownEngines[row.EngineName] {
		result.Verdict = VerdictFail
		result.Reason = fmt.Sprintf(
			"engine_name %q is not a registered engine", row.EngineName,
		)
		return result
	}

	result.Verdict = VerdictPass
	result.Reason = "known engine"
	return result
}
