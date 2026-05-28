// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Mock implementations for testing
type mockTesseraReader struct {
	entries map[uint64][]byte
}

func (m *mockTesseraReader) Read(ctx context.Context, index uint64) ([]byte, error) {
	entry, ok := m.entries[index]
	if !ok {
		return nil, fmt.Errorf("entry not found at index %d", index)
	}
	return entry, nil
}

func (m *mockTesseraReader) ReadCheckpoint(_ context.Context) ([]byte, error) {
	return []byte("tessera-log\n100\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), nil
}

type evidenceRow struct {
	certified       bool
	publisherIssuer string
	submittedBy     string
}

type mockPostgres struct {
	evidenceRows       map[uint64]evidenceRow
	witnessedIndices   map[uint64]bool
	registeredTargets  map[string]bool
	existingPolicies   map[string]bool
}

func (m *mockPostgres) QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*EvidenceRow, error) {
	row, ok := m.evidenceRows[logIndex]
	if !ok {
		return nil, nil
	}
	return &EvidenceRow{
		Certified:       row.certified,
		PublisherIssuer: row.publisherIssuer,
		SubmittedBy:     row.submittedBy,
	}, nil
}

func (m *mockPostgres) IsIndexWitnessed(ctx context.Context, index uint64) bool {
	return m.witnessedIndices[index]
}

func (m *mockPostgres) IsTargetRegistered(ctx context.Context, targetID string) bool {
	if m.registeredTargets == nil {
		return true
	}
	return m.registeredTargets[targetID]
}

func (m *mockPostgres) PolicyExistsByID(ctx context.Context, policyID string) bool {
	if m.existingPolicies == nil {
		return true
	}
	return m.existingPolicies[policyID]
}

func TestVerifier_VerifyEntry_AllChecksPass(t *testing.T) {
	// Setup: Mock Tessera (entry exists)
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: test"),
		},
	}

	// Setup: Mock PostgreSQL (entry certified, publisher trusted)
	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       true,
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
	}

	// Setup: Trusted publishers config
	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Name:         "github-scanners",
				Issuer:       "https://token.actions.githubusercontent.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog", "EnforcementLog"},
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	// Verify entry
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "Entry should pass all verification checks")
}

func TestVerifier_VerifyEntry_CertificationFailed(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog"),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       false, // Failed certification
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
	}

	config := &Config{TrustedPublishers: []TrustedPublisher{}}
	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail due to failed certification")
}

func TestVerifier_VerifyEntry_PublisherNotTrusted(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("metadata:\n  type: EvaluationLog"),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			42: {
				certified:       true,
				publisherIssuer: "https://untrusted-issuer.example.com",
				submittedBy:     "malicious-actor",
			},
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Issuer: "https://token.actions.githubusercontent.com",
				Sub:    "repo:complytime/*",
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail due to untrusted publisher")
}

func TestVerifier_VerifyEntry_TesseraReadFails(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{}, // Empty - no entries
	}
	mockDB := &mockPostgres{}
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
	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 999)
	assert.False(t, result, "Entry should fail when Tessera read fails")
}

func TestVerifier_VerifyEntry_MalformedYAML(t *testing.T) {
	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			42: []byte("{{invalid yaml}}"),
		},
	}
	mockDB := &mockPostgres{}
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
	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail with malformed YAML")
}

func TestVerifier_VerifyEntry_PolicyReferenceExists(t *testing.T) {
	// Setup: Policy artifact at log_index=0
	policyYAML := `metadata:
  type: Policy
requirements:
  - control-id: CC6.1
    title: Encryption at Rest
`

	// Setup: EvaluationLog references policy at log_index=0
	evaluationYAML := `metadata:
  type: EvaluationLog
  mapping-references:
    - id: soc2-policy
      tessera-log-index: 0
target:
  id: production
results:
  - control-id: CC6.1
    eval-result: pass
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			0:  []byte(policyYAML),
			42: []byte(evaluationYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			0: {
				certified:       true,
				publisherIssuer: "https://kubernetes.default.svc",
				submittedBy:     "system:serviceaccount:complytime:admin",
			},
			42: {
				certified:       true,
				publisherIssuer: "https://token.actions.githubusercontent.com",
				submittedBy:     "repo:complytime/scanner:ref:refs/heads/main",
			},
		},
		witnessedIndices: map[uint64]bool{
			0: true, // Policy is witnessed
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{
				Issuer:       "https://token.actions.githubusercontent.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog"},
			},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	// Verify entry (should check policy reference)
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "Entry should pass when policy reference exists and is witnessed")
}

func TestVerifier_VerifyEntry_PolicyReferenceNotWitnessed(t *testing.T) {
	policyYAML := `metadata:
  type: Policy
`
	evaluationYAML := `metadata:
  type: EvaluationLog
  mapping-references:
    - id: soc2-policy
      tessera-log-index: 0
target:
  id: production
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			0:  []byte(policyYAML),
			42: []byte(evaluationYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			0:  {certified: true, publisherIssuer: "https://kubernetes.default.svc", submittedBy: "system:serviceaccount:complytime:admin"},
			42: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/scanner:ref:refs/heads/main"},
		},
		witnessedIndices: map[uint64]bool{
			// Policy NOT witnessed
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://token.actions.githubusercontent.com", Sub: "repo:complytime/*", AllowedTypes: []string{"EvaluationLog"}},
			{Issuer: "https://kubernetes.default.svc", Sub: "system:serviceaccount:complytime:*", AllowedTypes: []string{"Policy"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)

	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "Entry should fail when policy reference is not witnessed")
}

func TestVerifier_VerifyEntry_AuditLogEvidenceReferencesValid(t *testing.T) {
	// EvaluationLog at index 1 with target "production"
	evaluationYAML := `metadata:
  type: EvaluationLog
target:
  id: production
`

	// AuditLog at index 42 references evidence at index 1
	auditYAML := `metadata:
  type: AuditLog
target:
  id: production
results:
  - control-id: CC6.1
    evidence:
      - tessera-log-index: 1
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			1:  []byte(evaluationYAML),
			42: []byte(auditYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			1: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
			42: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
		},
		witnessedIndices: map[uint64]bool{
			1: true, // Evidence is witnessed
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://token.actions.githubusercontent.com", Sub: "repo:complytime/*", AllowedTypes: []string{"AuditLog", "EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.True(t, result, "AuditLog should pass when evidence references are valid and targets match")
}

func TestVerifier_VerifyEntry_AuditLogTargetMismatch(t *testing.T) {
	// EvaluationLog with target "staging"
	evaluationYAML := `metadata:
  type: EvaluationLog
target:
  id: staging
`

	// AuditLog with target "production" references evidence from staging
	auditYAML := `metadata:
  type: AuditLog
target:
  id: production
results:
  - control-id: CC6.1
    evidence:
      - tessera-log-index: 1
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			1:  []byte(evaluationYAML),
			42: []byte(auditYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			1:  {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
			42: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
		},
		witnessedIndices: map[uint64]bool{1: true},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://token.actions.githubusercontent.com", Sub: "repo:complytime/*", AllowedTypes: []string{"AuditLog", "EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "AuditLog should fail when evidence targets don't match AuditLog target")
}

func TestVerifier_VerifyEntry_EvidenceReferenceWrongType(t *testing.T) {
	// Policy at index 1 (not valid evidence type)
	policyYAML := `metadata:
  type: Policy
target:
  id: production
`

	// AuditLog references policy as evidence (invalid)
	auditYAML := `metadata:
  type: AuditLog
target:
  id: production
results:
  - control-id: CC6.1
    evidence:
      - tessera-log-index: 1
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			1:  []byte(policyYAML),
			42: []byte(auditYAML),
		},
	}

	mockDB := &mockPostgres{
		evidenceRows: map[uint64]evidenceRow{
			1:  {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
			42: {certified: true, publisherIssuer: "https://token.actions.githubusercontent.com", submittedBy: "repo:complytime/*"},
		},
		witnessedIndices: map[uint64]bool{1: true},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://token.actions.githubusercontent.com", Sub: "repo:complytime/*", AllowedTypes: []string{"AuditLog", "Policy"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 42)
	assert.False(t, result, "AuditLog should fail when evidence reference points to non-evidence artifact type")
}

func TestVerifier_VerifyEntry_PolicyVerified(t *testing.T) {
	policyYAML := `metadata:
  type: Policy
  id: infra-baseline
  version: "2.0.0"
title: Infrastructure Baseline
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			10: []byte(policyYAML),
		},
	}

	mockDB := &mockPostgres{
		existingPolicies: map[string]bool{
			"infra-baseline": true,
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://example.com", Sub: "*", AllowedTypes: []string{"Policy"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 10)
	assert.True(t, result, "Policy entry should pass when policy exists in DB")
}

func TestVerifier_VerifyEntry_PolicyNotInDB(t *testing.T) {
	policyYAML := `metadata:
  type: Policy
  id: missing-policy
title: Missing Policy
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			10: []byte(policyYAML),
		},
	}

	mockDB := &mockPostgres{
		existingPolicies: map[string]bool{},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://example.com", Sub: "*", AllowedTypes: []string{"Policy"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 10)
	assert.False(t, result, "Policy entry should fail when policy not yet in DB")
}

func TestVerifier_VerifyEntry_TargetRegistrationVerified(t *testing.T) {
	targetYAML := `target:
  id: prod-cluster
  name: Production Cluster
  type: kubernetes-cluster
  technologies:
    - kubernetes
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			5: []byte(targetYAML),
		},
	}

	mockDB := &mockPostgres{
		registeredTargets: map[string]bool{
			"prod-cluster": true,
		},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://example.com", Sub: "*", AllowedTypes: []string{"EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 5)
	assert.True(t, result, "TargetRegistration should pass when target exists in DB")
}

func TestVerifier_VerifyEntry_TargetRegistrationNotInDB(t *testing.T) {
	targetYAML := `target:
  id: unknown-cluster
  name: Unknown Cluster
  type: kubernetes-cluster
  technologies:
    - kubernetes
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			5: []byte(targetYAML),
		},
	}

	mockDB := &mockPostgres{
		registeredTargets: map[string]bool{},
	}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://example.com", Sub: "*", AllowedTypes: []string{"EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
	result := verifier.VerifyEntry(context.Background(), 5)
	assert.False(t, result, "TargetRegistration should fail when target not in DB")
}

func TestVerifier_VerifyEntry_CatalogExistenceProof(t *testing.T) {
	catalogYAML := `metadata:
  type: ControlCatalog
  id: nist-800-53
controls:
  - id: AC-1
    title: Access Control Policy
`

	mockTessera := &mockTesseraReader{
		entries: map[uint64][]byte{
			20: []byte(catalogYAML),
		},
	}

	mockDB := &mockPostgres{}

	config := &Config{
		TrustedPublishers: []TrustedPublisher{
			{Issuer: "https://example.com", Sub: "*", AllowedTypes: []string{"EvaluationLog"}},
		},
	}

	verifier := NewVerifier(mockTessera, mockDB, config)
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
