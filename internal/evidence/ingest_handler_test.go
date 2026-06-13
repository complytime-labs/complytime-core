// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"testing"
)

func TestParseTargetRegistration_TrustedPublishers(t *testing.T) {
	yaml := []byte(`
metadata:
  type: TargetRegistration
  id: test-reg
  date: "2026-06-13T00:00:00Z"
target:
  id: test-target
  name: Test Target
  type: kubernetes-cluster
  trusted-publishers:
    - issuer: https://token.actions.githubusercontent.com
      sub_pattern: "repo:acme/scanner:*"
      environment: production
    - issuer: https://accounts.google.com
      sub_pattern: "scanner@acme.iam.gserviceaccount.com"
dimensions:
  technologies:
    - kubernetes
`)

	reg, err := ParseTargetRegistration(yaml)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(reg.Target.TrustedPublishers) != 2 {
		t.Fatalf("expected 2 trusted publishers, got %d", len(reg.Target.TrustedPublishers))
	}
	if reg.Target.TrustedPublishers[0].Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("unexpected issuer: %s", reg.Target.TrustedPublishers[0].Issuer)
	}
	if reg.Target.TrustedPublishers[0].Environment != "production" {
		t.Fatalf("unexpected environment: %s", reg.Target.TrustedPublishers[0].Environment)
	}
	if reg.Target.TrustedPublishers[1].SubPattern != "scanner@acme.iam.gserviceaccount.com" {
		t.Fatalf("unexpected sub_pattern: %s", reg.Target.TrustedPublishers[1].SubPattern)
	}
}

func TestParseTargetRegistration_RemovePublishers(t *testing.T) {
	yaml := []byte(`
metadata:
  type: TargetRegistration
  id: test-reg
  date: "2026-06-13T00:00:00Z"
target:
  id: test-target
  name: Test Target
  type: kubernetes-cluster
  remove-publishers:
    - issuer: https://old.example.com
      sub_pattern: "old-scanner@example.com"
`)

	reg, err := ParseTargetRegistration(yaml)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(reg.Target.RemovePublishers) != 1 {
		t.Fatalf("expected 1 remove publisher, got %d", len(reg.Target.RemovePublishers))
	}
	if reg.Target.RemovePublishers[0].Issuer != "https://old.example.com" {
		t.Fatalf("unexpected issuer: %s", reg.Target.RemovePublishers[0].Issuer)
	}
}

func TestParseTargetRegistration_NoPublishers_BackwardCompatible(t *testing.T) {
	yaml := []byte(`
metadata:
  type: TargetRegistration
  id: test-reg
  date: "2026-06-13T00:00:00Z"
target:
  id: test-target
  name: Test Target
  type: kubernetes-cluster
dimensions:
  technologies:
    - kubernetes
`)

	reg, err := ParseTargetRegistration(yaml)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(reg.Target.TrustedPublishers) != 0 {
		t.Fatalf("expected 0 trusted publishers, got %d", len(reg.Target.TrustedPublishers))
	}
	if len(reg.Target.RemovePublishers) != 0 {
		t.Fatalf("expected 0 remove publishers, got %d", len(reg.Target.RemovePublishers))
	}
}

func TestValidateTargetRegistration_Valid(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	reg.Target.TrustedPublishers = []TrustedPublisherYAML{
		{Issuer: "https://example.com", SubPattern: "repo:*"},
	}
	reg.Target.RemovePublishers = []RemovePublisherYAML{
		{Issuer: "https://other.com", SubPattern: "old:*"},
	}
	if err := ValidateTargetRegistration(reg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTargetRegistration_EmptyIssuer(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	reg.Target.TrustedPublishers = []TrustedPublisherYAML{
		{Issuer: "", SubPattern: "repo:*"},
	}
	if err := ValidateTargetRegistration(reg); err == nil {
		t.Fatal("expected error for empty issuer")
	}
}

func TestValidateTargetRegistration_EmptySubPattern(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	reg.Target.TrustedPublishers = []TrustedPublisherYAML{
		{Issuer: "https://example.com", SubPattern: ""},
	}
	if err := ValidateTargetRegistration(reg); err == nil {
		t.Fatal("expected error for empty sub_pattern")
	}
}

func TestValidateTargetRegistration_EmptyIssuerInRemove(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	reg.Target.RemovePublishers = []RemovePublisherYAML{
		{Issuer: "", SubPattern: "repo:*"},
	}
	if err := ValidateTargetRegistration(reg); err == nil {
		t.Fatal("expected error for empty issuer in remove-publishers")
	}
}

func TestValidateTargetRegistration_OverlapAddRemove(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	reg.Target.TrustedPublishers = []TrustedPublisherYAML{
		{Issuer: "https://example.com", SubPattern: "repo:*"},
	}
	reg.Target.RemovePublishers = []RemovePublisherYAML{
		{Issuer: "https://example.com", SubPattern: "repo:*"},
	}
	if err := ValidateTargetRegistration(reg); err == nil {
		t.Fatal("expected error for overlapping add/remove")
	}
}

func TestValidateTargetRegistration_BothEmpty(t *testing.T) {
	reg := &TargetRegistrationYAML{}
	reg.Target.ID = "test-target"
	if err := ValidateTargetRegistration(reg); err != nil {
		t.Fatalf("empty lists should be valid: %v", err)
	}
}
