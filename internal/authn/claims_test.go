package authn_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/authn"
)

func TestExtractClaimByPath_FlatStringSlice(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"admins", "auditors"},
	}
	got := authn.ExtractClaimByPath(claims, "groups")
	want := []string{"admins", "auditors"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractClaimByPath_NestedPath(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"complytime-admin", "uma_authorization"},
		},
	}
	got := authn.ExtractClaimByPath(claims, "realm_access.roles")
	if len(got) != 2 || got[0] != "complytime-admin" {
		t.Fatalf("got %v, want [complytime-admin uma_authorization]", got)
	}
}

func TestExtractClaimByPath_MissingPath(t *testing.T) {
	claims := map[string]any{"sub": "user1"}
	got := authn.ExtractClaimByPath(claims, "groups")
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestExtractClaimByPath_EmptyPath(t *testing.T) {
	claims := map[string]any{"groups": []any{"admins"}}
	got := authn.ExtractClaimByPath(claims, "")
	if len(got) != 0 {
		t.Fatalf("expected empty for empty path, got %v", got)
	}
}

func TestExtractClaimByPath_NonArrayLeaf(t *testing.T) {
	claims := map[string]any{"name": "alice"}
	got := authn.ExtractClaimByPath(claims, "name")
	if len(got) != 0 {
		t.Fatalf("expected empty for non-array leaf, got %v", got)
	}
}

func TestExtractClaimByPath_DeeplyNested(t *testing.T) {
	claims := map[string]any{
		"resource_access": map[string]any{
			"complytime": map[string]any{
				"roles": []any{"admin", "publisher"},
			},
		},
	}
	got := authn.ExtractClaimByPath(claims, "resource_access.complytime.roles")
	if len(got) != 2 || got[0] != "admin" || got[1] != "publisher" {
		t.Fatalf("got %v, want [admin publisher]", got)
	}
}

func TestExtractClaimByPath_NonStringElements(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"admins", 42, true, "auditors"},
	}
	got := authn.ExtractClaimByPath(claims, "groups")
	if len(got) != 2 || got[0] != "admins" || got[1] != "auditors" {
		t.Fatalf("expected only string elements, got %v", got)
	}
}
