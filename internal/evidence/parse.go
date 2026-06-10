// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"fmt"

	gemara "github.com/gemaraproj/go-gemara"
)

// ParseAndFlattenEvidence parses Gemara YAML (EvaluationLog or EnforcementLog)
// and returns flattened evidence records ready for insertion. Extracted from the
// HTTP ingest handler so the ConnectRPC service can reuse the same logic.
func ParseAndFlattenEvidence(ctx context.Context, data []byte) ([]EvidenceRecord, string, error) {
	if len(data) == 0 {
		return nil, "", fmt.Errorf("empty YAML content")
	}
	artifactType, err := DetectArtifactType(data)
	if err != nil {
		return nil, "", err
	}

	var rows []EvidenceRow
	var policyID string

	switch artifactType {
	case gemara.EvaluationLogArtifact:
		rows, policyID, err = FlattenEvaluation(ctx, data)
	case gemara.EnforcementLogArtifact:
		rows, policyID, err = FlattenEnforcement(ctx, data)
	default:
		return nil, "", fmt.Errorf(
			"unsupported artifact type %q — expected EvaluationLog or EnforcementLog",
			artifactType,
		)
	}
	if err != nil {
		return nil, "", fmt.Errorf("flatten %s: %w", artifactType, err)
	}

	return ToEvidenceRecords(rows), policyID, nil
}
