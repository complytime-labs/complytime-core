// SPDX-License-Identifier: Apache-2.0

package gemara

import (
	"testing"
	"time"
)

func TestParseAuditLog_MixedClassifications(t *testing.T) {
	content := `
metadata:
  id: audit-complyctl-bp
  type: AuditLog
  gemara-version: "1.0.0"
  description: Branch protection audit for complyctl
  date: "2026-04-16T10:00:00Z"
  author:
    id: studio-assistant
    name: ComplyTime Studio
    type: Software Assisted
  mapping-references:
    - id: bp-catalog
      title: AMPEL Branch Protection
      version: "1.0"
target:
  id: github.com/complytime/complyctl
  name: complyctl
  type: Software
summary: Mixed results across controls.
criteria:
  - reference-id: bp-catalog
results:
  - id: r1
    title: BP-1 check
    type: Strength
    description: Branch protection enabled
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
    evidence:
      - type: EvaluationLog
        collected-at: "2026-04-07T10:00:00Z"
        location:
          reference-id: bp-catalog
        description: evaluation result
  - id: r2
    title: BP-2 check
    type: Finding
    description: Reviews not required
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
  - id: r3
    title: BP-3 check
    type: Gap
    description: No status checks
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
  - id: r4
    title: BP-4 check
    type: Strength
    description: Force push disabled
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
  - id: r5
    title: BP-5 check
    type: Observation
    description: Branch deletion allowed
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
  - id: r6
    title: BP-6 check
    type: Strength
    description: Signed commits
    criteria-reference:
      reference-id: bp-catalog
      entries:
        - reference-id: bp-catalog
`
	s, err := ParseAuditLog(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Strengths != 3 {
		t.Errorf("strengths: got %d, want 3", s.Strengths)
	}
	if s.Findings != 1 {
		t.Errorf("findings: got %d, want 1", s.Findings)
	}
	if s.Gaps != 1 {
		t.Errorf("gaps: got %d, want 1", s.Gaps)
	}
	if s.Observations != 1 {
		t.Errorf("observations: got %d, want 1", s.Observations)
	}
	if s.TargetID != "github.com/complytime/complyctl" {
		t.Errorf("target_id: got %q", s.TargetID)
	}
	if s.Framework != "AMPEL Branch Protection" {
		t.Errorf("framework: got %q", s.Framework)
	}

	expectedEnd := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	if !s.AuditEnd.Equal(expectedEnd) {
		t.Errorf("audit_end: got %v, want %v", s.AuditEnd, expectedEnd)
	}

	expectedStart := time.Date(2026, 4, 7, 10, 0, 0, 0, time.UTC)
	if !s.AuditStart.Equal(expectedStart) {
		t.Errorf("audit_start: got %v, want %v", s.AuditStart, expectedStart)
	}
}

func TestParseAuditLog_InvalidYAML(t *testing.T) {
	_, err := ParseAuditLog("not: [valid: yaml: {{")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseAuditLog_MissingResults(t *testing.T) {
	content := `
metadata:
  id: empty-audit
  type: AuditLog
  gemara-version: "1.0.0"
  description: No results
  author:
    id: test
    name: Test
    type: Software Assisted
target:
  id: some-target
  name: target
  type: Software
summary: No results
criteria:
  - reference-id: ref
results: []
`
	_, err := ParseAuditLog(content)
	if err == nil {
		t.Fatal("expected error for empty results")
	}
}

func TestParseAuditLog_NoEvidence_FallbackDates(t *testing.T) {
	content := `
metadata:
  id: no-evidence-audit
  type: AuditLog
  gemara-version: "1.0.0"
  description: Audit without evidence timestamps
  date: "2026-04-10T12:00:00Z"
  author:
    id: test
    name: Test
    type: Software Assisted
target:
  id: my-target
  name: my-target
  type: Software
summary: All good.
criteria:
  - reference-id: ref
results:
  - id: r1
    title: Check 1
    type: Strength
    description: Passed
    criteria-reference:
      reference-id: ref
      entries:
        - reference-id: ref
`
	s, err := ParseAuditLog(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedDate := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	if !s.AuditStart.Equal(expectedDate) {
		t.Errorf("audit_start fallback: got %v, want %v", s.AuditStart, expectedDate)
	}
	if !s.AuditEnd.Equal(expectedDate) {
		t.Errorf("audit_end fallback: got %v, want %v", s.AuditEnd, expectedDate)
	}
}
