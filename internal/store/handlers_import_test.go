// SPDX-License-Identifier: Apache-2.0

package store

import (
	"strings"
	"testing"
)

func TestImportPublisherIdentity_TracksReference(t *testing.T) {
	ref := "ghcr.io/org/bundle:v1.0.0"
	identity := importPublisherIdentity(ref)

	if !strings.HasPrefix(identity.Sub, "import:") {
		t.Fatalf("Sub = %q, want prefix 'import:'", identity.Sub)
	}
	if !strings.Contains(identity.Sub, ref) {
		t.Fatalf("Sub = %q, want to contain reference %q", identity.Sub, ref)
	}
	if identity.Issuer != "complytime-gateway" {
		t.Fatalf("Issuer = %q, want 'complytime-gateway'", identity.Issuer)
	}
	if identity.Type != "import" {
		t.Fatalf("Type = %q, want 'import'", identity.Type)
	}
}

func TestImportPublisherIdentity_UniquePerReference(t *testing.T) {
	id1 := importPublisherIdentity("ghcr.io/org/bundle-a:v1")
	id2 := importPublisherIdentity("ghcr.io/org/bundle-b:v1")

	if id1.Sub == id2.Sub {
		t.Fatal("different references should produce different Sub values")
	}
}
