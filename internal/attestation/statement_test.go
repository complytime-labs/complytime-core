// internal/attestation/statement_test.go
package attestation_test

import (
	"encoding/json"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/attestation"
)

func TestWrapAsReceipt(t *testing.T) {
	content := []byte("metadata:\n  type: EvaluationLog\ntarget:\n  id: pkg:oci/acme/myapp\n")
	pub := attestation.PublisherMeta{
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "repo:acme/myapp",
		Method:  "jwt-channel",
	}

	wrapped, err := attestation.WrapAsReceipt(content, pub, "EvaluationLog", "pkg:oci/acme/myapp")
	if err != nil {
		t.Fatalf("WrapAsReceipt failed: %v", err)
	}

	var stmt attestation.Statement
	if err := json.Unmarshal(wrapped, &stmt); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if stmt.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("got type %q, want in-toto v1", stmt.Type)
	}
	if stmt.PredicateType != "https://complytime.dev/gemara-receipt/v1" {
		t.Errorf("got predicateType %q", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("got %d subjects, want 1", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "pkg:oci/acme/myapp" {
		t.Errorf("got subject name %q", stmt.Subject[0].Name)
	}
	if stmt.Subject[0].Digest["sha256"] == "" {
		t.Error("missing sha256 digest")
	}
	if stmt.Predicate.ArtifactType != "EvaluationLog" {
		t.Errorf("got artifact type %q", stmt.Predicate.ArtifactType)
	}
	if stmt.Predicate.Publisher.Issuer != pub.Issuer {
		t.Errorf("got publisher issuer %q", stmt.Predicate.Publisher.Issuer)
	}
}

func TestUnwrap(t *testing.T) {
	content := []byte("metadata:\n  type: EvaluationLog\n")
	pub := attestation.PublisherMeta{
		Issuer:  "https://example.com",
		Subject: "test-user",
		Method:  "jwt-channel",
	}

	wrapped, err := attestation.WrapAsReceipt(content, pub, "EvaluationLog", "pkg:oci/acme/myapp")
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	unwrapped, stmt, err := attestation.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if string(unwrapped) != string(content) {
		t.Errorf("content mismatch: got %q", string(unwrapped))
	}
	if stmt.Predicate.Publisher.Subject != "test-user" {
		t.Errorf("publisher mismatch: got %q", stmt.Predicate.Publisher.Subject)
	}
}

func TestUnwrapRawYAML(t *testing.T) {
	raw := []byte("metadata:\n  type: EvaluationLog\n")

	unwrapped, stmt, err := attestation.Unwrap(raw)
	if err != nil {
		t.Fatalf("unwrap raw YAML failed: %v", err)
	}
	if string(unwrapped) != string(raw) {
		t.Errorf("content mismatch")
	}
	if stmt != nil {
		t.Error("expected nil statement for raw YAML")
	}
}
