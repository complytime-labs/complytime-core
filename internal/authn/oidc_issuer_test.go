package authn_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/authn"
)

func TestExtractScopes_KnownScopes(t *testing.T) {
	claims := map[string]any{
		"scope": "complytime:admin complytime:audit openid profile",
	}
	scopes := authn.ExtractScopes(claims)
	if !contains(scopes, "complytime:admin") {
		t.Errorf("expected complytime:admin in scopes, got %v", scopes)
	}
	if !contains(scopes, "complytime:audit") {
		t.Errorf("expected complytime:audit in scopes, got %v", scopes)
	}
	if contains(scopes, "openid") {
		t.Errorf("openid should be filtered out, got %v", scopes)
	}
	if contains(scopes, "profile") {
		t.Errorf("profile should be filtered out, got %v", scopes)
	}
}

func TestExtractScopes_ReadScope(t *testing.T) {
	claims := map[string]any{
		"scope": "complytime:read",
	}
	scopes := authn.ExtractScopes(claims)
	if !contains(scopes, "complytime:read") {
		t.Errorf("expected complytime:read, got %v", scopes)
	}
}

func TestExtractScopes_NoScopeClaim(t *testing.T) {
	claims := map[string]any{"sub": "user1"}
	scopes := authn.ExtractScopes(claims)
	if len(scopes) != 0 {
		t.Errorf("expected empty scopes, got %v", scopes)
	}
}

func TestExtractScopes_EmptyScope(t *testing.T) {
	claims := map[string]any{"scope": ""}
	scopes := authn.ExtractScopes(claims)
	if len(scopes) != 0 {
		t.Errorf("expected empty scopes, got %v", scopes)
	}
}

func TestExtractScopes_UnknownOnly(t *testing.T) {
	claims := map[string]any{"scope": "openid profile email"}
	scopes := authn.ExtractScopes(claims)
	if len(scopes) != 0 {
		t.Errorf("expected all scopes filtered, got %v", scopes)
	}
}

func TestExtractGroups_FlatClaim(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"complytime-admin", "complytime-auditor", "other-app-role"},
	}
	groups := authn.ExtractGroups(claims, "groups")
	if len(groups) != 2 {
		t.Fatalf("expected 2 known groups, got %v", groups)
	}
	if !contains(groups, "complytime-admin") {
		t.Errorf("expected complytime-admin, got %v", groups)
	}
	if !contains(groups, "complytime-auditor") {
		t.Errorf("expected complytime-auditor, got %v", groups)
	}
}

func TestExtractGroups_NestedKeycloakClaim(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"complytime-admin", "uma_authorization"},
		},
	}
	groups := authn.ExtractGroups(claims, "realm_access.roles")
	if len(groups) != 1 || groups[0] != "complytime-admin" {
		t.Fatalf("expected [complytime-admin] (uma_authorization filtered), got %v", groups)
	}
}

func TestExtractGroups_CaseNormalization(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"ComplyTime-Admin", "COMPLYTIME-AUDITOR"},
	}
	groups := authn.ExtractGroups(claims, "groups")
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups after normalization, got %v", groups)
	}
	if !contains(groups, "complytime-admin") {
		t.Errorf("expected lowercase complytime-admin, got %v", groups)
	}
	if !contains(groups, "complytime-auditor") {
		t.Errorf("expected lowercase complytime-auditor, got %v", groups)
	}
}

func TestExtractGroups_UnknownGroupsFiltered(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"hr-payroll", "engineering", "other-app-admin"},
	}
	groups := authn.ExtractGroups(claims, "groups")
	if len(groups) != 0 {
		t.Fatalf("expected all unknown groups filtered, got %v", groups)
	}
}

func TestExtractGroups_EmptyGroupClaim(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"complytime-admin"},
	}
	groups := authn.ExtractGroups(claims, "")
	if len(groups) != 0 {
		t.Fatalf("expected nil when groupClaim is empty, got %v", groups)
	}
}

func TestExtractGroups_MissingClaim(t *testing.T) {
	claims := map[string]any{"sub": "user1"}
	groups := authn.ExtractGroups(claims, "groups")
	if len(groups) != 0 {
		t.Fatalf("expected nil for missing claim, got %v", groups)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
