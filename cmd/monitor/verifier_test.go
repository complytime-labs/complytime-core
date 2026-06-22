// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockTesseraReader struct {
	entries map[uint64][]byte
}

func (m *mockTesseraReader) Read(_ context.Context, index uint64) ([]byte, error) {
	entry, ok := m.entries[index]
	if !ok {
		return nil, fmt.Errorf("entry not found at index %d", index)
	}
	return entry, nil
}

func (m *mockTesseraReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return []byte("tessera-log\n100\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), nil
}

func trustedConfig() *Config {
	return &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Name:         "github-scanners",
				Issuer:       "https://token.actions.githubusercontent.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog", "EnforcementLog", "AuditLog"},
			},
		},
	}
}

func TestVerifier_VerifyEntry_EvaluationLog(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog\npublisher:\n  issuer: https://token.actions.githubusercontent.com\n  sub: repo:complytime/scanner\ntarget:\n  id: test"),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "EvaluationLog with trusted publisher should pass")
}

func TestVerifier_VerifyEntry_PublisherNotTrusted(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog\npublisher:\n  issuer: https://untrusted.example.com\n  sub: malicious-actor"),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail due to untrusted publisher")
}

func TestVerifier_VerifyEntry_TesseraReadFails(t *testing.T) {
	mockTessera := &mockTesseraReader{entries: map[uint64][]byte{}}

	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com"},
		},
	}
	verifier := NewVerifier(mockTessera, config)

	result := verifier.VerifyEntry(context.Background(), 999)
	assert.False(t, result, "Entry should fail when Tessera read fails")
}

func TestVerifier_VerifyEntry_MalformedYAML(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("{{invalid yaml}}"),
		},
	}

	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com"},
		},
	}
	verifier := NewVerifier(mockTessera, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail with malformed YAML")
}

func TestVerifier_VerifyEntry_PolicyReferenceExists(t *testing.T) {
	policyYAML := "metadata:\n  type: Policy\n  id: soc2-policy\ntitle: SOC2 Policy\n"

	evaluationYAML := "metadata:\n  type: EvaluationLog\n  mapping-references:\n    - id: soc2-policy\n      tessera-log-index: 0\npublisher:\n  issuer: https://token.actions.githubusercontent.com\n  sub: repo:complytime/scanner\ntarget:\n  id: production\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			0:  []byte(policyYAML),
			42: []byte(evaluationYAML),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "Entry should pass when policy reference exists")
}

func TestVerifier_VerifyEntry_PolicyReferenceNotFound(t *testing.T) {
	evaluationYAML := "metadata:\n  type: EvaluationLog\n  mapping-references:\n    - id: soc2-policy\n      tessera-log-index: 99\npublisher:\n  issuer: https://token.actions.githubusercontent.com\n  sub: repo:complytime/scanner\ntarget:\n  id: production\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte(evaluationYAML),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail when policy reference not found in Tessera")
}

func TestVerifier_VerifyEntry_AuditLogValid(t *testing.T) {
	evaluationYAML := "metadata:\n  type: EvaluationLog\ntarget:\n  id: production\n"

	auditYAML := "metadata:\n  type: AuditLog\npublisher:\n  issuer: https://token.actions.githubusercontent.com\n  sub: repo:complytime/auditor\ntarget:\n  id: production\nresults:\n  - control-id: CC6.1\n    evidence:\n      - tessera-log-index: 1\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			1:  []byte(evaluationYAML),
			42: []byte(auditYAML),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "AuditLog should pass when evidence references are valid and targets match")
}

func TestVerifier_VerifyEntry_AuditLogTargetMismatch(t *testing.T) {
	evaluationYAML := "metadata:\n  type: EvaluationLog\ntarget:\n  id: staging\n"

	auditYAML := "metadata:\n  type: AuditLog\npublisher:\n  issuer: https://token.actions.githubusercontent.com\n  sub: repo:complytime/auditor\ntarget:\n  id: production\nresults:\n  - control-id: CC6.1\n    evidence:\n      - tessera-log-index: 1\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			1:  []byte(evaluationYAML),
			42: []byte(auditYAML),
		},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "AuditLog should fail when evidence targets don't match")
}

func TestVerifier_VerifyEntry_PolicyVerified(t *testing.T) {
	policyYAML := "metadata:\n  type: Policy\n  id: infra-baseline\n  version: \"2.0.0\"\ntitle: Infrastructure Baseline\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{10: []byte(policyYAML)},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 10)
	assert.True(t, result, "Policy entry should pass verification")
}

func TestVerifier_VerifyEntry_TargetRegistration(t *testing.T) {
	targetYAML := "target:\n  id: prod-cluster\n  name: Production Cluster\n  type: kubernetes-cluster\n  technologies:\n    - kubernetes\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{5: []byte(targetYAML)},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 5)
	assert.True(t, result, "TargetRegistration should pass verification")
}

func TestVerifier_VerifyEntry_CatalogExistenceProof(t *testing.T) {
	catalogYAML := "metadata:\n  type: ControlCatalog\n  id: nist-800-53\ncontrols:\n  - id: AC-1\n    title: Access Control Policy\n"

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{20: []byte(catalogYAML)},
	}

	verifier := NewVerifier(mockTessera, trustedConfig())
	result := verifier.VerifyEntry(context.Background(), 20)
	assert.True(t, result, "Catalog entry should pass with existence proof only")
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		text    string
		want    bool
	}{
		{"repo:complytime/*", "repo:complytime/scanner:ref:refs/heads/main", true},
		{"repo:complytime/*", "repo:other/scanner", false},
		{"exact-match", "exact-match", true},
		{"exact-match", "different", false},
		{"*", "anything", true},
		{"", "", true},
		{"pattern", "", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.text), func(t *testing.T) {
			got := globMatch(tt.pattern, tt.text)
			assert.Equal(t, tt.want, got)
		})
	}
}
