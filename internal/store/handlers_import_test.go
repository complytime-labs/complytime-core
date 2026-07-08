// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"strings"
	"testing"

	gemarabundle "github.com/gemaraproj/go-gemara/bundle"
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

// TestProcessBundleFiles_SkipsTargetScopedArtifacts verifies that bundle files
// carrying a target.id never reach the Tessera appender.
func TestProcessBundleFiles_SkipsTargetScopedArtifacts(t *testing.T) {
	catalogYAML := []byte(`
metadata:
  type: ControlCatalog
  id: nist-800-53
`)
	evidenceYAML := []byte(`
metadata:
  type: EvaluationLog
target:
  id: prod-api
`)

	var appended [][]byte
	appender := &mockAppender{addFn: func(_ context.Context, data []byte) (uint64, error) {
		appended = append(appended, data)
		return uint64(len(appended) - 1), nil
	}}

	s := Stores{
		TesseraAppender: appender,
		IngestPublisher: &mockIngestPublisher{},
		IngestTracker:   NewIngestTracker(),
	}
	defer s.IngestTracker.Stop()

	files := []gemarabundle.File{
		{Name: "catalog.yaml", Data: catalogYAML},
		{Name: "evidence.yaml", Data: evidenceYAML},
	}

	imported := processBundleFiles(context.Background(), files, s, "bundle-1", "ghcr.io/org/bundle:v1")

	if len(imported) != 1 {
		t.Fatalf("imported count = %d, want 1 (catalog only)", len(imported))
	}
	if imported[0].Name != "catalog.yaml" {
		t.Errorf("imported artifact = %q, want catalog.yaml", imported[0].Name)
	}
	if len(appended) != 1 {
		t.Errorf("TesseraAppender.Add called %d time(s), want 1 — target-scoped artifact must be skipped", len(appended))
	}
}
