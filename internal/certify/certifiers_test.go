// SPDX-License-Identifier: Apache-2.0

package certify

import (
	"context"
	"testing"
	"time"
)

// --- Schema Certifier ---

func validRow() EvidenceRow {
	return EvidenceRow{
		EvidenceID:       "ev-1",
		TargetID:         "target-1",
		RuleID:           "rule-1",
		EvalResult:       "Passed",
		ComplianceStatus: "Compliant",
		CollectedAt:      time.Now().Add(-1 * time.Hour),
	}
}

func TestSchemaCertifier_Pass(t *testing.T) {
	c := &SchemaCertifier{}
	r := c.Certify(context.Background(), validRow())
	if r.Verdict != VerdictPass {
		t.Errorf("expected pass, got %s: %s", r.Verdict, r.Reason)
	}
}

func TestSchemaCertifier_MissingTargetID(t *testing.T) {
	c := &SchemaCertifier{}
	row := validRow()
	row.TargetID = ""
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestSchemaCertifier_InvalidEvalResult(t *testing.T) {
	c := &SchemaCertifier{}
	row := validRow()
	row.EvalResult = "Bogus"
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestSchemaCertifier_FutureTimestamp(t *testing.T) {
	c := &SchemaCertifier{}
	row := validRow()
	row.CollectedAt = time.Now().Add(1 * time.Hour)
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail || r.Reason != "collected_at is in the future" {
		t.Errorf("expected fail with future reason, got %s: %s", r.Verdict, r.Reason)
	}
}

func TestSchemaCertifier_ZeroTimestamp(t *testing.T) {
	c := &SchemaCertifier{}
	row := validRow()
	row.CollectedAt = time.Time{}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

// --- Provenance Certifier ---

func TestProvenanceCertifier_BothPresent(t *testing.T) {
	c := &ProvenanceCertifier{}
	row := EvidenceRow{SourceRegistry: "reg.io", AttestationRef: "sha256:abc"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictPass {
		t.Errorf("expected pass, got %s: %s", r.Verdict, r.Reason)
	}
}

func TestProvenanceCertifier_NoProvenance(t *testing.T) {
	c := &ProvenanceCertifier{}
	r := c.Certify(context.Background(), EvidenceRow{})
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestProvenanceCertifier_UnknownRegistry(t *testing.T) {
	c := &ProvenanceCertifier{KnownRegistries: map[string]bool{"trusted.io": true}}
	row := EvidenceRow{SourceRegistry: "evil.io"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestProvenanceCertifier_KnownRegistry(t *testing.T) {
	c := &ProvenanceCertifier{KnownRegistries: map[string]bool{"trusted.io": true}}
	row := EvidenceRow{SourceRegistry: "trusted.io"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictPass {
		t.Errorf("expected pass, got %s: %s", r.Verdict, r.Reason)
	}
}

// --- Executor Certifier ---

func TestExecutorCertifier_KnownEngine(t *testing.T) {
	c := &ExecutorCertifier{KnownEngines: map[string]bool{"nessus": true}}
	row := EvidenceRow{EngineName: "nessus"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictPass {
		t.Errorf("expected pass, got %s: %s", r.Verdict, r.Reason)
	}
}

func TestExecutorCertifier_UnknownEngine(t *testing.T) {
	c := &ExecutorCertifier{KnownEngines: map[string]bool{"nessus": true}}
	row := EvidenceRow{EngineName: "rogue-scanner"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestExecutorCertifier_MissingEngine(t *testing.T) {
	c := &ExecutorCertifier{}
	r := c.Certify(context.Background(), EvidenceRow{})
	if r.Verdict != VerdictFail {
		t.Errorf("expected fail, got %s", r.Verdict)
	}
}

func TestExecutorCertifier_SkipEnrichmentOnly(t *testing.T) {
	c := &ExecutorCertifier{}
	row := EvidenceRow{EnrichmentStatus: "Skipped"}
	r := c.Certify(context.Background(), row)
	if r.Verdict != VerdictSkip {
		t.Errorf("expected skip, got %s: %s", r.Verdict, r.Reason)
	}
}
