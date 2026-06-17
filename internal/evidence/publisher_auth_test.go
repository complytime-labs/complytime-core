// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func TestIsPublisherAuthorized_ExactMatch(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/app:ref:refs/heads/main"},
	}
	if !IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:ref:refs/heads/main", publishers) {
		t.Fatal("expected exact match to authorize")
	}
}

func TestIsPublisherAuthorized_WildcardMatch(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/app:*"},
	}
	if !IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:ref:refs/heads/main", publishers) {
		t.Fatal("expected wildcard match to authorize")
	}
	if !IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:environment:production", publishers) {
		t.Fatal("expected wildcard match for different suffix to authorize")
	}
}

func TestIsPublisherAuthorized_NoMatch(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/app:ref:refs/heads/main"},
	}
	if IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:other/app:ref:refs/heads/main", publishers) {
		t.Fatal("expected non-matching sub to be rejected")
	}
}

func TestIsPublisherAuthorized_IssuerMismatch(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/app:*"},
	}
	if IsPublisherAuthorized("https://accounts.google.com", "repo:acme/app:ref:refs/heads/main", publishers) {
		t.Fatal("expected issuer mismatch to be rejected")
	}
}

func TestIsPublisherAuthorized_EmptyList(t *testing.T) {
	t.Parallel()
	if IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:ref:refs/heads/main", nil) {
		t.Fatal("expected empty list to reject")
	}
	if IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:ref:refs/heads/main", []requirements.TrustedPublisherRow{}) {
		t.Fatal("expected empty list to reject")
	}
}

func TestIsPublisherAuthorized_MultiplePublishers(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://accounts.google.com", SubPattern: "scanner@acme.iam.gserviceaccount.com"},
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "repo:acme/app:*"},
	}
	// Match second entry
	if !IsPublisherAuthorized("https://token.actions.githubusercontent.com", "repo:acme/app:ref:refs/heads/main", publishers) {
		t.Fatal("expected match on second publisher entry")
	}
	// Match first entry
	if !IsPublisherAuthorized("https://accounts.google.com", "scanner@acme.iam.gserviceaccount.com", publishers) {
		t.Fatal("expected match on first publisher entry")
	}
}

func TestIsPublisherAuthorized_WildcardOnlyAsterisk(t *testing.T) {
	t.Parallel()
	publishers := []requirements.TrustedPublisherRow{
		{Issuer: "https://token.actions.githubusercontent.com", SubPattern: "*"},
	}
	// A pattern of "*" means prefix is "", so anything with the right issuer matches.
	if !IsPublisherAuthorized("https://token.actions.githubusercontent.com", "anything-goes", publishers) {
		t.Fatal("expected bare wildcard to match any subject with the right issuer")
	}
}

func TestMatchSubPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		subject string
		want    bool
	}{
		{"repo:acme/app:ref:refs/heads/main", "repo:acme/app:ref:refs/heads/main", true},
		{"repo:acme/app:ref:refs/heads/main", "repo:acme/app:ref:refs/heads/dev", false},
		{"repo:acme/app:*", "repo:acme/app:ref:refs/heads/main", true},
		{"repo:acme/app:*", "repo:acme/app:", true},
		{"repo:acme/app:*", "repo:other/app:ref:refs/heads/main", false},
		{"*", "anything", true},
		{"*", "", true},
		{"exact", "exact", true},
		{"exact", "exact-longer", false},
	}
	for _, tt := range tests {
		got := matchSubPattern(tt.pattern, tt.subject)
		if got != tt.want {
			t.Errorf("matchSubPattern(%q, %q) = %v, want %v", tt.pattern, tt.subject, got, tt.want)
		}
	}
}
