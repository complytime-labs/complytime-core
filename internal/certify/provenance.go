// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"context"
	"fmt"
)

const provenanceVersion = "1.0.0"

// ProvenanceCertifier checks that evidence has a traceable origin:
// at least one of source_registry or attestation_ref must be present.
// When source_registry is present it is checked against known registries.
type ProvenanceCertifier struct {
	KnownRegistries map[string]bool
}

func (c *ProvenanceCertifier) Name() string    { return "provenance" }
func (c *ProvenanceCertifier) Version() string { return provenanceVersion }

func (c *ProvenanceCertifier) Certify(_ context.Context, row EvidenceRow) CertResult {
	result := CertResult{Certifier: c.Name(), Version: c.Version()}

	hasRegistry := row.SourceRegistry != ""
	hasAttestation := row.AttestationRef != ""

	if !hasRegistry && !hasAttestation {
		result.Verdict = VerdictFail
		result.Reason = "no source_registry or attestation_ref"
		return result
	}

	if hasRegistry && len(c.KnownRegistries) > 0 {
		if !c.KnownRegistries[row.SourceRegistry] {
			result.Verdict = VerdictFail
			result.Reason = fmt.Sprintf(
				"source_registry %q is not a known registry",
				row.SourceRegistry,
			)
			return result
		}
		result.Reason = "known registry"
	} else {
		result.Reason = "provenance fields present"
	}

	result.Verdict = VerdictPass
	return result
}
