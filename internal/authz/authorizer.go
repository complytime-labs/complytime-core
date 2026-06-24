// SPDX-License-Identifier: Apache-2.0

package authz

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/cedar-policy/cedar-go"
)

//go:embed policies/base.cedar
var defaultPolicies []byte

// Authorizer provides Cedar-based authorization.
type Authorizer struct {
	policies atomic.Pointer[cedar.PolicySet]
}

// NewAuthorizer creates an authorizer, loading Cedar policies from policyDir.
// If policyDir is empty, uses embedded default policies.
func NewAuthorizer(policyDir string) (*Authorizer, error) {
	a := &Authorizer{}
	if err := a.loadPolicies(policyDir); err != nil {
		return nil, err
	}
	return a, nil
}

// IsAuthorized evaluates whether the principal is authorized to perform the action on the resource.
func (a *Authorizer) IsAuthorized(principal cedar.EntityUID, principalAttrs map[string]cedar.Value, action cedar.EntityUID, resource cedar.EntityUID, resourceAttrs map[string]cedar.Value) (bool, error) {
	ps := a.policies.Load()
	if ps == nil {
		return false, fmt.Errorf("no policies loaded")
	}

	entities := make(cedar.EntityMap)

	// Add principal entity
	if len(principalAttrs) > 0 {
		recMap := make(cedar.RecordMap)
		for k, v := range principalAttrs {
			recMap[cedar.String(k)] = v
		}
		entities[principal] = cedar.Entity{
			UID:        principal,
			Attributes: cedar.NewRecord(recMap),
		}
	}

	// Add resource entity
	if len(resourceAttrs) > 0 {
		recMap := make(cedar.RecordMap)
		for k, v := range resourceAttrs {
			recMap[cedar.String(k)] = v
		}
		entities[resource] = cedar.Entity{
			UID:        resource,
			Attributes: cedar.NewRecord(recMap),
		}
	}

	req := cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
	}

	decision, diag := cedar.Authorize(ps, entities, req)
	if len(diag.Errors) > 0 {
		return false, fmt.Errorf("authorization errors: %v", diag.Errors)
	}

	return decision == cedar.Allow, nil
}

// Reload reloads policies from policyDir. Swaps atomically. Keeps last good policy set on error.
func (a *Authorizer) Reload(policyDir string) error {
	return a.loadPolicies(policyDir)
}

// loadPolicies loads Cedar policies from directory or embedded defaults.
func (a *Authorizer) loadPolicies(policyDir string) error {
	var ps *cedar.PolicySet
	var err error

	if policyDir == "" {
		ps, err = cedar.NewPolicySetFromBytes("base.cedar", defaultPolicies)
	} else {
		// Read all .cedar files from directory
		entries, readErr := os.ReadDir(policyDir)
		if readErr != nil {
			return fmt.Errorf("failed to read policy directory: %w", readErr)
		}

		// Always start with embedded defaults
		combined := append([]byte{}, defaultPolicies...)
		combined = append(combined, '\n')

		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".cedar" {
				continue
			}
			content, readErr := os.ReadFile(filepath.Join(policyDir, entry.Name()))
			if readErr != nil {
				return fmt.Errorf("failed to read policy file %s: %w", entry.Name(), readErr)
			}
			combined = append(combined, content...)
			combined = append(combined, '\n')
		}

		ps, err = cedar.NewPolicySetFromBytes("combined.cedar", combined)
	}

	if err != nil {
		return fmt.Errorf("failed to parse policies: %w", err)
	}

	a.policies.Store(ps)
	return nil
}
