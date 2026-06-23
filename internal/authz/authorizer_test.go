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
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0644); err != nil {
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

func TestIsAuthorized_Register_AllowedForAny(t *testing.T) {
	a, err := NewAuthorizer("")
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "eve@example.com")
	action := cedar.NewEntityUID("Action", "register")
	resource := cedar.NewEntityUID("Resource", "system")

	allowed, err := a.IsAuthorized(principal, nil, action, resource, nil)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("register should be allowed for any identity")
	}
}

func TestIsAuthorized_Submit_WithMatchingPublisherTrust(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "submit.cedar")
	policy := `permit(
  principal,
  action == Action::"submit",
  resource
) when {
  resource has trustedPublishers && resource.trustedPublishers.contains(principal.issuer)
};`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "frank@example.com")
	action := cedar.NewEntityUID("Action", "submit")
	resource := cedar.NewEntityUID("Target", "project-1")

	principalAttrs := map[string]cedar.Value{
		"issuer": cedar.String("https://github.com"),
	}
	resourceAttrs := map[string]cedar.Value{
		"trustedPublishers": cedar.NewSet(cedar.String("https://github.com")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, resourceAttrs)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if !allowed {
		t.Error("submit should be allowed with matching publisher trust")
	}
}

func TestIsAuthorized_Submit_WithoutMatchingPublisherTrust(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "submit.cedar")
	policy := `permit(
  principal,
  action == Action::"submit",
  resource
) when {
  resource has trustedPublishers && resource.trustedPublishers.contains(principal.issuer)
};`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	principal := cedar.NewEntityUID("Identity", "grace@example.com")
	action := cedar.NewEntityUID("Action", "submit")
	resource := cedar.NewEntityUID("Target", "project-1")

	principalAttrs := map[string]cedar.Value{
		"issuer": cedar.String("https://gitlab.com"),
	}
	resourceAttrs := map[string]cedar.Value{
		"trustedPublishers": cedar.NewSet(cedar.String("https://github.com")),
	}

	allowed, err := a.IsAuthorized(principal, principalAttrs, action, resource, resourceAttrs)
	if err != nil {
		t.Fatalf("IsAuthorized failed: %v", err)
	}
	if allowed {
		t.Error("submit should be denied without matching publisher trust")
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

func TestReload_SwapsAtomically(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test.cedar")
	if err := os.WriteFile(policyFile, []byte(`permit(principal, action, resource);`), 0644); err != nil {
		t.Fatal(err)
	}

	a, err := NewAuthorizer(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	oldPS := a.policies.Load()

	// Modify policy file
	if err := os.WriteFile(policyFile, []byte(`forbid(principal, action, resource);`), 0644); err != nil {
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
