// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"context"
	"log/slog"
	"time"

	"github.com/complytime-labs/complytime-core/internal/bus"
)

// CertificationQuerier fetches recently ingested evidence rows for a policy.
type CertificationQuerier interface {
	QueryRecentEvidence(
		ctx context.Context, policyID string, since time.Time,
	) ([]EvidenceRow, error)
}

// CertificationWriter persists certification results as trust signals.
type CertificationWriter interface {
	InsertTrustSignals(ctx context.Context, signals []TrustSignalRow) error
}

// inferLayer maps certifier names to trust signal layers.
func inferLayer(certifierName string) string {
	switch certifierName {
	case "schema", "quality", "freshness", "relevance":
		return "quality"
	case "provenance", "executor", "identity":
		return "identity"
	case "publisher_auth", "attestation", "signature":
		return "attestation"
	default:
		return "quality"
	}
}

// CertificationHandler returns a debounce-compatible handler that runs the
// certifier pipeline against recently ingested evidence for a policy.
func CertificationHandler(
	ctx context.Context,
	pipeline *Pipeline,
	querier CertificationQuerier,
	writer CertificationWriter,
) func(bus.EvidenceEvent) {
	return func(evt bus.EvidenceEvent) {
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

			var trustSignals []TrustSignalRow
			for _, r := range results {
				trustSignals = append(trustSignals, TrustSignalRow{
					EvidenceID: row.EvidenceID,
					Layer:      inferLayer(r.Certifier),
					CheckName:  r.Certifier,
					Result:     Result(r.Verdict),
					Reason:     r.Reason,
					CheckedAt:  time.Now(),
				})
			}

			if err := writer.InsertTrustSignals(ctx, trustSignals); err != nil {
				slog.Warn("trust signal insert failed",
					"evidence_id", row.EvidenceID, "error", err)
				continue
			}

			slog.Info("evidence certification complete",
				"evidence_id", row.EvidenceID,
				"trust_signals", len(trustSignals),
				"policy_id", evt.PolicyID,
			)
		}
	}
}
