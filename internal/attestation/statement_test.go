// SPDX-License-Identifier: Apache-2.0

package attestation_test

import (
	"testing"

	v1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"

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

	var stmt v1.Statement
	if err := protojson.Unmarshal(wrapped, &stmt); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if stmt.GetType() != v1.StatementTypeUri {
		t.Errorf("got type %q, want %q", stmt.GetType(), v1.StatementTypeUri)
	}
	if stmt.GetPredicateType() != "https://complytime.dev/gemara-receipt/v1" {
		t.Errorf("got predicateType %q", stmt.GetPredicateType())
	}
	if len(stmt.GetSubject()) != 1 {
		t.Fatalf("got %d subjects, want 1", len(stmt.GetSubject()))
	}
	if stmt.GetSubject()[0].GetName() != "pkg:oci/acme/myapp" {
		t.Errorf("got subject name %q", stmt.GetSubject()[0].GetName())
	}
	if stmt.GetSubject()[0].GetDigest()["sha256"] == "" {
		t.Error("missing sha256 digest")
	}

	predFields := stmt.GetPredicate().GetFields()
	if predFields["artifactType"].GetStringValue() != "EvaluationLog" {
		t.Errorf("got artifact type %q", predFields["artifactType"].GetStringValue())
	}
	pubFields := predFields["publisher"].GetStructValue().GetFields()
	if pubFields["issuer"].GetStringValue() != pub.Issuer {
		t.Errorf("got publisher issuer %q", pubFields["issuer"].GetStringValue())
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
	if stmt.Publisher.Subject != "test-user" {
		t.Errorf("publisher mismatch: got %q", stmt.Publisher.Subject)
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
