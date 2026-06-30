// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

func TestNewAuthorizer_FromDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatalf("NewAuthorizer failed: %v", err)
	}
	if a.policies.Load() == nil {
		t.Error("policies not loaded")
	}
}

func TestNewAuthorizer_EmbeddedDefaults(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatalf("NewAuthorizer with embedded defaults failed: %v", err)
	}
	if a.policies.Load() == nil {
		t.Error("embedded policies not loaded")
	}
}

func TestIsAuthorized_ReadStatus_AllowedForAny(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "alice@example.com")
	action := cedar.NewEntityUID("Action", "read:status")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("read:status should be allowed for any identity")
	}
}

func TestIsAuthorized_ReadCheckpoint_AllowedForAny(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "bob@example.com")
	action := cedar.NewEntityUID("Action", "read:checkpoint")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("read:checkpoint should be allowed for any identity")
	}
}

func TestIsAuthorized_ReadEntries_DeniedWithoutAuditorsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "charlie@example.com")
	action := cedar.NewEntityUID("Action", "read:entries")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("charlie@example.com"),
		"groups": cedar.NewSet(),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("read:entries should be denied without auditors group")
	}
}

func TestIsAuthorized_ReadEntries_AllowedWithAuditorsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "dana@example.com")
	action := cedar.NewEntityUID("Action", "read:entries")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("dana@example.com"),
		"groups": cedar.NewSet(cedar.String("auditors")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("read:entries should be allowed with auditors group")
	}
}

func TestIsAuthorized_Publish_DeniedWithoutPublishersGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "alice@example.com")
	action := cedar.NewEntityUID("Action", "publish")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("alice@example.com"),
		"groups": cedar.NewSet(),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("publish should be denied without publishers group")
	}
}

func TestIsAuthorized_Publish_AllowedWithPublishersGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "ci@example.com")
	action := cedar.NewEntityUID("Action", "publish")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("ci@example.com"),
		"groups": cedar.NewSet(cedar.String("publishers")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("publish should be allowed with publishers group")
	}
}

func TestIsAuthorized_Publish_ForbidCannotBeOverridden(t *testing.T) {
	tmpDir := t.TempDir()
	// Try to override the forbid with a blanket permit
	override := `permit(principal, action == Action::"publish", resource);`
	if err := os.WriteFile(filepath.Join(tmpDir, "override.cedar"), []byte(override), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "attacker@example.com")
	action := cedar.NewEntityUID("Action", "publish")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("attacker@example.com"),
		"groups": cedar.NewSet(),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("forbid should prevent directory policy from overriding publishers group requirement")
	}
}

func TestIsAuthorized_ReadEntries_ForbidCannotBeOverridden(t *testing.T) {
	tmpDir := t.TempDir()
	override := `permit(principal, action == Action::"read:entries", resource);`
	if err := os.WriteFile(filepath.Join(tmpDir, "override.cedar"), []byte(override), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "attacker@example.com")
	action := cedar.NewEntityUID("Action", "read:entries")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email": cedar.String("attacker@example.com"),
		"name":  cedar.String("attacker"),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("forbid should prevent directory policy from overriding auditors group requirement")
	}
}

func TestIsAuthorized_PublishArtifact_DeniedWithoutTrust(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "ci@example.com")
	action := cedar.NewEntityUID("Action", "publish:artifact")
	resource := cedar.NewEntityUID("Target", "project-1")

	resourceAttrs := map[string]cedar.Value{
		"publisher_trusted": cedar.Boolean(false),
	}

	allowed, err := a.IsAuthorized(principal, nil, action, resource, resourceAttrs)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("publish:artifact should be denied without publisher trust")
	}
}

func TestIsAuthorized_PublishArtifact_AllowedWithTrust(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "ci@example.com")
	action := cedar.NewEntityUID("Action", "publish:artifact")
	resource := cedar.NewEntityUID("Target", "project-1")

	resourceAttrs := map[string]cedar.Value{
		"publisher_trusted": cedar.Boolean(true),
	}

	allowed, err := a.IsAuthorized(principal, nil, action, resource, resourceAttrs)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("publish:artifact should be allowed with publisher trust")
	}
}

func TestIsAuthorized_PublishRegistration_Denied(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "ci@example.com")
	action := cedar.NewEntityUID("Action", "publish:registration")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("publish:registration should be denied (removed from policy)")
	}
}

func TestIsAuthorized_PublishPolicy_Denied(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "ci@example.com")
	action := cedar.NewEntityUID("Action", "publish:policy")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("publish:policy should be denied (removed from policy)")
	}
}

func TestIsAuthorized_ReadEntries_DeniedWithNoGroupsKey(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "user@example.com")
	action := cedar.NewEntityUID("Action", "read:entries")
	resource := cedar.NewEntityUID("Resource", "system")

	// email and name present, but NO groups key at all
	principalAttrs := map[string]cedar.Value{
		"email": cedar.String("user@example.com"),
		"name":  cedar.String("user"),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("read:entries should be denied when groups key is absent (not just empty)")
	}
}

func TestIsAuthorized_UnknownAction_Denied(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "heidi@example.com")
	action := cedar.NewEntityUID("Action", "unknown:action")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("unknown action should be denied")
	}
}

func TestIsAuthorized_AdminRegisterTarget_DeniedWithoutAdminsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "user@example.com")
	action := cedar.NewEntityUID("Action", "admin:register-target")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("user@example.com"),
		"groups": cedar.NewSet(),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("admin:register-target should be denied without admins group")
	}
}

func TestIsAuthorized_AdminRegisterTarget_AllowedWithAdminsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "admin@example.com")
	action := cedar.NewEntityUID("Action", "admin:register-target")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("admin@example.com"),
		"groups": cedar.NewSet(cedar.String("admins")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("admin:register-target should be allowed with admins group")
	}
}

func TestIsAuthorized_AdminManageTrust_DeniedWithoutAdminsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "user@example.com")
	action := cedar.NewEntityUID("Action", "admin:manage-trust")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("admin:manage-trust should be denied without admins group")
	}
}

func TestIsAuthorized_AdminManageTrust_AllowedWithAdminsGroup(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "admin@example.com")
	action := cedar.NewEntityUID("Action", "admin:manage-trust")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("admin@example.com"),
		"groups": cedar.NewSet(cedar.String("admins")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("admin:manage-trust should be allowed with admins group")
	}
}

func TestIsAuthorized_AdminRegisterTarget_ForbidCannotBeOverridden(t *testing.T) {
	tmpDir := t.TempDir()
	// Try to override the forbid with a blanket permit
	override := `permit(principal, action == Action::"admin:register-target", resource);`
	if err := os.WriteFile(filepath.Join(tmpDir, "override.cedar"), []byte(override), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "attacker@example.com")
	action := cedar.NewEntityUID("Action", "admin:register-target")
	resource := cedar.NewEntityUID("Resource", "system")

	principalAttrs := map[string]cedar.Value{
		"email":  cedar.String("attacker@example.com"),
		"groups": cedar.NewSet(),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("forbid should prevent directory policy from overriding admins group requirement")
	}
}

func TestReload_SwapsAtomically(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	oldPS := a.policies.Load()

	// Modify policy file
	if err := os.WriteFile(policyFile, []byte(`forbid(principal, action, resource);`), 0600); err != nil {
		t.Fatal(err)
	}

	if err := a.Reload(tmpDir); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	newPS := a.policies.Load()
	if oldPS == newPS {
		t.Error("policy set should have been swapped")
	}
}

func TestLoadPolicies_MergesWithEmbeddedDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	// Write a policy that adds a new action (doesn't exist in embedded defaults)
	extraPolicy := `permit(principal, action == Action::"custom:action", resource);`
	if err := os.WriteFile(filepath.Join(tmpDir, "extra.cedar"), []byte(extraPolicy), 0600); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatalf("NewAuthorizer failed: %v", err)
	}

	// The custom action from directory should be permitted
	principal := cedar.NewEntityUID("Identity", "test@example.com")
	resource := cedar.NewEntityUID("Resource", "system")
	customAction := cedar.NewEntityUID("Action", "custom:action")

	allowed, err := a.IsAuthorized(principal, nil, customAction, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("custom:action from directory policy should be permitted")
	}

	// The embedded read:status should ALSO be permitted (merged, not replaced)
	statusAction := cedar.NewEntityUID("Action", "read:status")
	allowed, err = a.IsAuthorized(principal, nil, statusAction, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("read:status from embedded policy should still be permitted after merge")
	}
}
