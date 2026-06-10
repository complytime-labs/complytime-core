// SPDX-License-Identifier: Apache-2.0

package posture

import "context"

// RequirementStore defines read operations for the requirement matrix.
type RequirementStore interface {
	ListRequirementMatrix(ctx context.Context, f RequirementFilter) ([]RequirementRow, error)
	ListRequirementEvidence(ctx context.Context, requirementID string, f RequirementFilter) ([]RequirementEvidenceRow, error)
}

// InventoryStore lists evidence inventory aggregates by target.
type InventoryStore interface {
	ListInventory(ctx context.Context, filters InventoryFilter) ([]InventoryItem, error)
}
