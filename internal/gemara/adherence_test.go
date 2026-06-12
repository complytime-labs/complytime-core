// SPDX-License-Identifier: Apache-2.0

package gemara

import (
	"testing"
	"time"
)

func TestExtractAdherenceFrequencies(t *testing.T) {
	yaml := `
metadata:
  type: Policy
  id: pol-1
title: Test
adherence:
  assessment-plans:
    - id: plan-1
      requirement-id: AC-1.1
      frequency: monthly
      evaluation-methods:
        - id: eval-1
          type: Behavioral
          mode: Automated
          required: true
    - id: plan-2
      requirement-id: AC-2.1
      frequency: quarterly
    - id: plan-3
      requirement-id: AC-3.1
      frequency: weekly
    - id: plan-4
      requirement-id: CM-1.1
      frequency: annually
`
	freqs := ExtractAdherenceFrequencies(yaml)
	if freqs == nil {
		t.Fatal("expected non-nil frequencies")
	}

	cases := map[string]time.Duration{
		"AC-1.1": 30 * 24 * time.Hour,
		"AC-2.1": 90 * 24 * time.Hour,
		"AC-3.1": 7 * 24 * time.Hour,
		"CM-1.1": 365 * 24 * time.Hour,
	}
	for reqID, want := range cases {
		got, ok := freqs[reqID]
		if !ok {
			t.Errorf("missing frequency for %s", reqID)
			continue
		}
		if got != want {
			t.Errorf("frequency for %s: got %v, want %v", reqID, got, want)
		}
	}
}

func TestExtractAdherenceFrequencies_Empty(t *testing.T) {
	yaml := `
metadata:
  type: Policy
  id: pol-1
title: Test
`
	freqs := ExtractAdherenceFrequencies(yaml)
	if freqs != nil {
		t.Errorf("expected nil for policy without assessment plans, got %v", freqs)
	}
}

func TestExtractAdherenceFrequencies_InvalidYAML(t *testing.T) {
	freqs := ExtractAdherenceFrequencies("not: [valid: yaml")
	if freqs != nil {
		t.Errorf("expected nil for invalid YAML, got %v", freqs)
	}
}

func TestExtractAdherenceFrequencies_UnknownFrequency(t *testing.T) {
	yaml := `
adherence:
  assessment-plans:
    - id: plan-1
      requirement-id: AC-1.1
      frequency: biweekly
`
	freqs := ExtractAdherenceFrequencies(yaml)
	if freqs != nil {
		t.Errorf("expected nil for unknown frequency, got %v", freqs)
	}
}
