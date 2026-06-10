// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"

	"github.com/complytime-labs/complytime-core/internal/evidence"
)

// ParseAndFlattenEvidence parses Gemara YAML (EvaluationLog or EnforcementLog)
// and returns flattened evidence records ready for insertion.
func ParseAndFlattenEvidence(ctx context.Context, data []byte) ([]EvidenceRecord, string, error) {
	return evidence.ParseAndFlattenEvidence(ctx, data)
}
