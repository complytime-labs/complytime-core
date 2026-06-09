// SPDX-License-Identifier: Apache-2.0

// Effective policy resolution logic adapted from
// github.com/gemaraproj/go-gemara/policy.go (unpublished).
// Resolves a Policy's catalog imports against available catalogs,
// applies overlays (exclusions, AR modifications), and returns
// the effective controls and assessment requirements.

package gemara

import (
	"fmt"

	sdk "github.com/gemaraproj/go-gemara"
)

// EffectiveControls is a resolved ControlCatalog with policy overlays applied.
type EffectiveControls struct {
	CatalogID string
	Controls  []sdk.Control
}

// ResolveEffectiveControls matches a policy's catalog imports to the
// provided catalogs, applies exclusions and AR modifications, and
// returns the resulting controls per catalog.
func ResolveEffectiveControls(pol sdk.Policy, catalogs []sdk.ControlCatalog) ([]EffectiveControls, error) {
	refIndex := buildRefIndex(pol.Metadata.MappingReferences)
	catalogsByID := make(map[string]sdk.ControlCatalog, len(catalogs))
	for _, c := range catalogs {
		catalogsByID[c.Metadata.Id] = c
	}

	var result []EffectiveControls
	for _, imp := range pol.Imports.Catalogs {
		metaID, ok := refIndex[imp.ReferenceId]
		if !ok {
			continue
		}
		cat, ok := catalogsByID[metaID]
		if !ok {
			continue
		}

		controls := flattenControls(cat, catalogs)
		controls = applyExclusions(controls, imp.Exclusions)
		controls = applyARModifications(controls, imp.AssessmentRequirementModifications)

		result = append(result, EffectiveControls{
			CatalogID: cat.Metadata.Id,
			Controls:  controls,
		})
	}

	if len(result) == 0 && len(pol.Imports.Catalogs) > 0 {
		return nil, fmt.Errorf("no catalog imports could be resolved for policy %s", pol.Metadata.Id)
	}
	return result, nil
}

// ResolveGuidanceRefsFromPolicy extracts guidance catalog IDs from a
// parsed Policy's imports.guidance section by resolving each reference-id
// through the policy's mapping-references index.
func ResolveGuidanceRefsFromPolicy(pol sdk.Policy) []string {
	refIndex := buildRefIndex(pol.Metadata.MappingReferences)
	var ids []string
	for _, imp := range pol.Imports.Guidance {
		if metaID, ok := refIndex[imp.ReferenceId]; ok {
			ids = append(ids, metaID)
		}
	}
	return ids
}

// ResolveGuidanceRefs parses raw policy YAML content and returns the
// guidance catalog IDs referenced in imports.guidance. Returns nil
// (not an error) if the content cannot be parsed or has no guidance imports.
func ResolveGuidanceRefs(content string) []string {
	var partial struct {
		Metadata struct {
			Type              string                 `yaml:"type"`
			MappingReferences []sdk.MappingReference `yaml:"mapping-references"`
		} `yaml:"metadata"`
		Imports struct {
			Guidance []struct {
				ReferenceId string `yaml:"reference-id"`
			} `yaml:"guidance"`
		} `yaml:"imports"`
	}
	if err := UnmarshalYAML([]byte(content), &partial); err != nil {
		return nil
	}
	if partial.Metadata.Type != "Policy" || len(partial.Imports.Guidance) == 0 {
		return nil
	}
	refIndex := make(map[string]string, len(partial.Metadata.MappingReferences))
	for _, ref := range partial.Metadata.MappingReferences {
		refIndex[ref.Id] = ref.Id
	}
	var ids []string
	for _, imp := range partial.Imports.Guidance {
		if metaID, ok := refIndex[imp.ReferenceId]; ok {
			ids = append(ids, metaID)
		}
	}
	return ids
}

// ExtractControlRows converts effective controls into database-ready rows.
func ExtractControlRows(eff []EffectiveControls, policyID string) ([]ControlRow, []AssessmentRequirementRow, []ControlThreatRow) {
	var controls []ControlRow
	var reqs []AssessmentRequirementRow
	var threats []ControlThreatRow

	for _, ec := range eff {
		for _, c := range ec.Controls {
			state := lifecycleString(c.State)
			controls = append(controls, ControlRow{
				CatalogID: ec.CatalogID,
				ControlID: c.Id,
				Title:     c.Title,
				Objective: c.Objective,
				GroupID:   c.Group,
				State:     state,
				PolicyID:  policyID,
			})
			for _, ar := range c.AssessmentRequirements {
				reqs = append(reqs, AssessmentRequirementRow{
					CatalogID:      ec.CatalogID,
					ControlID:      c.Id,
					RequirementID:  ar.Id,
					Text:           ar.Text,
					Applicability:  ar.Applicability,
					Recommendation: ar.Recommendation,
					State:          lifecycleString(ar.State),
				})
			}
			for _, mem := range c.Threats {
				for _, ent := range mem.Entries {
					threats = append(threats, ControlThreatRow{
						CatalogID:         ec.CatalogID,
						ControlID:         c.Id,
						ThreatReferenceID: mem.ReferenceId,
						ThreatEntryID:     ent.ReferenceId,
					})
				}
			}
		}
	}
	return controls, reqs, threats
}

func buildRefIndex(refs []sdk.MappingReference) map[string]string {
	idx := make(map[string]string, len(refs))
	for _, ref := range refs {
		idx[ref.Id] = ref.Id
	}
	return idx
}

func flattenControls(primary sdk.ControlCatalog, pool []sdk.ControlCatalog) []sdk.Control {
	controls := make([]sdk.Control, len(primary.Controls))
	copy(controls, primary.Controls)

	if len(primary.Extends) == 0 {
		return controls
	}
	for _, cat := range pool {
		if cat.Metadata.Id == primary.Metadata.Id {
			continue
		}
		controls = append(controls, cat.Controls...)
	}
	return controls
}

func applyExclusions(controls []sdk.Control, exclusions []string) []sdk.Control {
	if len(exclusions) == 0 {
		return controls
	}
	excluded := toSet(exclusions)
	filtered := make([]sdk.Control, 0, len(controls))
	for _, c := range controls {
		if !excluded[c.Id] {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func applyARModifications(controls []sdk.Control, mods []sdk.AssessmentRequirementModifier) []sdk.Control {
	if len(mods) == 0 {
		return controls
	}

	modsByTarget := make(map[string][]sdk.AssessmentRequirementModifier, len(mods))
	for _, m := range mods {
		modsByTarget[m.TargetId] = append(modsByTarget[m.TargetId], m)
	}

	for i, ctrl := range controls {
		var modified []sdk.AssessmentRequirement
		for _, ar := range ctrl.AssessmentRequirements {
			targetMods, hasMods := modsByTarget[ar.Id]
			if !hasMods {
				modified = append(modified, ar)
				continue
			}

			removed := false
			for _, m := range targetMods {
				switch m.ModificationType {
				case sdk.ModRemove:
					removed = true
				case sdk.ModReplace, sdk.ModOverride:
					ar = replaceAR(ar, m)
				case sdk.ModModify:
					ar = replaceAR(ar, m)
				case sdk.ModAdd:
					modified = append(modified, ar)
					ar = newARFromMod(m)
				}
			}
			if !removed {
				modified = append(modified, ar)
			}
		}
		controls[i].AssessmentRequirements = modified
	}
	return controls
}

func replaceAR(ar sdk.AssessmentRequirement, m sdk.AssessmentRequirementModifier) sdk.AssessmentRequirement {
	if m.Text != "" {
		ar.Text = m.Text
	}
	if len(m.Applicability) > 0 {
		ar.Applicability = m.Applicability
	}
	if m.Recommendation != "" {
		ar.Recommendation = m.Recommendation
	}
	return ar
}

func newARFromMod(m sdk.AssessmentRequirementModifier) sdk.AssessmentRequirement {
	return sdk.AssessmentRequirement{
		Id:             m.Id,
		Text:           m.Text,
		Applicability:  m.Applicability,
		Recommendation: m.Recommendation,
		State:          sdk.LifecycleActive,
	}
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
