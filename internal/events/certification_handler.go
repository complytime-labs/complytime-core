// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/complytime-labs/complytime-core/internal/certifier"
)

// CertificationQuerier fetches recently ingested evidence rows for a policy.
type CertificationQuerier interface {
	QueryRecentEvidence(
		ctx context.Context, policyID string, since time.Time,
	) ([]certifier.EvidenceRow, error)
}

// CertificationWriter persists certification results and updates evidence.
type CertificationWriter interface {
	InsertCertifications(
		ctx context.Context, results []CertificationRow,
	) error
	UpdateEvidenceCertified(
		ctx context.Context, evidenceID string, certified bool,
	) error
}

// CertificationRow is the insert shape for the certifications table.
type CertificationRow struct {
	EvidenceID       string
	Certifier        string
	CertifierVersion string
	Result           string
	Reason           string
}

// CertificationHandler returns a debounce-compatible handler that runs the
// certifier pipeline against recently ingested evidence for a policy.
func CertificationHandler(
	ctx context.Context,
	pipeline *certifier.Pipeline,
	querier CertificationQuerier,
	writer CertificationWriter,
) func(EvidenceEvent) {
	return func(evt EvidenceEvent) {
		since := evt.Timestamp.Add(-5 * time.Minute)
		rows, err := querier.QueryRecentEvidence(ctx, evt.PolicyID, since)
		if err != nil {
			slog.Warn("certification query failed",
				"policy_id", evt.PolicyID, "error", err)
			return
		}
		if len(rows) == 0 {
			slog.Debug("no evidence rows for certification",
				"policy_id", evt.PolicyID)
			return
		}

		for _, row := range rows {
			results := pipeline.Run(ctx, row)

			var certRows []CertificationRow
			for _, r := range results {
				certRows = append(certRows, CertificationRow{
					EvidenceID:       row.EvidenceID,
					Certifier:        r.Certifier,
					CertifierVersion: r.Version,
					Result:           string(r.Verdict),
					Reason:           r.Reason,
				})
			}

			if err := writer.InsertCertifications(ctx, certRows); err != nil {
				slog.Warn("certification insert failed",
					"evidence_id", row.EvidenceID, "error", err)
				continue
			}

			certified := certifier.IsCertified(results)
			if err := writer.UpdateEvidenceCertified(
				ctx, row.EvidenceID, certified,
			); err != nil {
				slog.Warn("evidence certified update failed",
					"evidence_id", row.EvidenceID, "error", err)
			} else {
				slog.Info("evidence certified",
					"evidence_id", row.EvidenceID,
					"certified", fmt.Sprintf("%t", certified),
					"policy_id", evt.PolicyID,
				)
			}
		}
	}
}
