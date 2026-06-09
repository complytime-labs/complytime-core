// SPDX-License-Identifier: Apache-2.0

package gemara

import (
	"fmt"

	sdk "github.com/gemaraproj/go-gemara"
	goyaml "github.com/goccy/go-yaml"
)

// MappingEntry represents a single control-to-framework reference parsed from a mapping document.
type MappingEntry struct {
	MappingID       string `json:"mapping_id"`
	SourceCatalogID string `json:"source_catalog_id"`
	TargetCatalogID string `json:"target_catalog_id"`
	GuidelineID     string `json:"guideline_id"`
	ControlID       string `json:"control_id"`
	RequirementID   string `json:"requirement_id"`
	Framework       string `json:"framework"`
	Reference       string `json:"reference"`
	Strength        uint8  `json:"strength"`
	Confidence      string `json:"confidence"`
}

// ParseMappingEntries extracts structured mapping entries from a Gemara
// MappingDocument's YAML content. Uses go-gemara types for schema-aware parsing.
// sourceCatalogID and targetCatalogID identify the global crosswalk (e.g. "soc2-2024" -> "ccc-v4").
//
// Field semantics for a guidance->control crosswalk:
//   - GuidelineID = m.Source (source guideline reference, joins guidance_entries.guideline_id)
//   - ControlID   = t.EntryId (target control reference, joins controls.control_id)
func ParseMappingEntries(content, mappingID, sourceCatalogID, targetCatalogID, framework string) ([]MappingEntry, error) {
	var doc sdk.MappingDocument
	if err := goyaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("parse mapping YAML: %w", err)
	}

	var entries []MappingEntry
	for _, m := range doc.Mappings {
		for _, t := range m.Targets {
			strength := uint8(0)
			if t.Strength > 0 && t.Strength <= 10 {
				strength = uint8(t.Strength) //nolint:gosec // G115: strength is 0-100
			}
			entries = append(entries, MappingEntry{
				MappingID:       mappingID,
				SourceCatalogID: sourceCatalogID,
				TargetCatalogID: targetCatalogID,
				GuidelineID:     m.Source,
				ControlID:       t.EntryId,
				RequirementID:   m.Id,
				Framework:       framework,
				Reference:       t.EntryId,
				Strength:        strength,
				Confidence:      t.ConfidenceLevel.String(),
			})
		}
	}
	return entries, nil
}
