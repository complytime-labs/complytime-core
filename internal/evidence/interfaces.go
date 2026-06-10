// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"time"
)

// EvidenceStore defines read/write operations for evidence records.
type EvidenceStore interface {
	InsertEvidence(ctx context.Context, records []EvidenceRecord) (int, error)
	QueryEvidence(ctx context.Context, f EvidenceFilter) ([]EvidenceRecord, error)
}

// CertificationStore defines read/write operations for evidence certifications.
type CertificationStore interface {
	InsertCertifications(ctx context.Context, rows []CertificationRow) error
	QueryCertifications(ctx context.Context, evidenceID string) ([]CertificationRow, error)
	QueryRecentEvidence(
		ctx context.Context, policyID string, since time.Time,
	) ([]EvidenceRowLite, error)
}
