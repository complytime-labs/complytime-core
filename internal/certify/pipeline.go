// SPDX-License-Identifier: Apache-2.0

package certify

import "context"

// Pipeline runs a sequence of certifiers against an evidence row.
// All certifiers execute regardless of prior verdicts (no short-circuit).
type Pipeline struct {
	certifiers []Certifier
}

// NewPipeline creates a pipeline with the given certifiers in execution order.
func NewPipeline(certifiers ...Certifier) *Pipeline {
	return &Pipeline{certifiers: certifiers}
}

// Run executes every registered certifier against the row and returns
// all results. The caller decides how to interpret the aggregate.
func (p *Pipeline) Run(ctx context.Context, row EvidenceRow) []CertResult {
	results := make([]CertResult, 0, len(p.certifiers))
	for _, c := range p.certifiers {
		results = append(results, c.Certify(ctx, row))
	}
	return results
}
