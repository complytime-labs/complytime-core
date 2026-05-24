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

type evidenceRow struct {
	certified       bool
	publisherIssuer string
	submittedBy     string
}

type mockPostgres struct {
	evidenceRows map[uint64]evidenceRow
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
