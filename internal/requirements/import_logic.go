// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gemara "github.com/gemaraproj/go-gemara"
	gemarabundle "github.com/gemaraproj/go-gemara/bundle"
	"github.com/google/uuid"

	gemarapkg "github.com/complytime-labs/complytime-core/internal/gemara"
)

// StorePolicyFromContent parses a Policy YAML and stores it.
func StorePolicyFromContent(ctx context.Context, ps PolicyStore, ctrlS ControlStore, content string, opts ...PolicyIngestOption) (OciImportedArtifact, error) {
	var pol gemara.Policy
	if err := gemarapkg.UnmarshalYAML([]byte(content), &pol); err != nil {
		return OciImportedArtifact{}, err
	}
	title := strings.TrimSpace(pol.Title)
	if title == "" {
		title = strings.TrimSpace(pol.Metadata.Id)
	}
	if title == "" {
		title = "Imported policy"
	}
	pid := strings.TrimSpace(pol.Metadata.Id)
	if pid == "" {
		pid = uuid.NewString()
	}
	// Normalize nil slices to empty slices for database insert
	// (nil slice is treated as NULL which violates NOT NULL constraint)
	p := Policy{
		PolicyID:     pid,
		Title:        title,
		Version:      pol.Metadata.Version,
		Content:      content,
		Technologies: NormalizeSlice(pol.Scope.In.Technologies),
		Geopolitical: NormalizeSlice(pol.Scope.In.Geopolitical),
		Sensitivity:  NormalizeSlice(pol.Scope.In.Sensitivity),
		Users:        NormalizeSlice(pol.Scope.In.Users),
		Groups:       NormalizeSlice(pol.Scope.In.Groups),
	}

	if len(opts) > 0 {
		opt := opts[0]
		p.TesseraLogIndex = &opt.LogIndex
		p.BundleID = opt.BundleID
	}

	// Extract evaluation timeline
	if start := string(pol.ImplementationPlan.EvaluationTimeline.Start); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			p.EvaluationTimelineStart = &t
		}
	}
	if end := string(pol.ImplementationPlan.EvaluationTimeline.End); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			p.EvaluationTimelineEnd = &t
		}
	}

	if err := ps.InsertPolicy(ctx, p); err != nil {
		return OciImportedArtifact{}, err
	}
	if ctrlS != nil {
		if _, err := ExtractPolicyCriteria(ctx, p.PolicyID, content, ctrlS); err != nil {
			slog.Warn("inline criteria extraction failed", "policy_id", p.PolicyID, "error", err)
		}
	}
	return OciImportedArtifact{Type: "Policy", ID: p.PolicyID, Name: title}, nil
}

// StoreMappingFromContent parses a MappingDocument YAML and stores it.
func StoreMappingFromContent(ctx context.Context, ms MappingStore, content string) (OciImportedArtifact, error) {
	var doc gemara.MappingDocument
	if err := gemarapkg.UnmarshalYAML([]byte(content), &doc); err != nil {
		return OciImportedArtifact{}, err
	}
	src := strings.TrimSpace(doc.SourceReference.ReferenceId)
	tgt := strings.TrimSpace(doc.TargetReference.ReferenceId)
	mid := strings.TrimSpace(doc.Metadata.Id)
	if mid == "" {
		mid = uuid.NewString()
	}
	m := MappingDocument{
		MappingID:       mid,
		SourceCatalogID: src,
		TargetCatalogID: tgt,
		Framework:       strings.TrimSpace(doc.Title),
		Content:         content,
	}
	if err := ms.InsertMapping(ctx, m); err != nil {
		return OciImportedArtifact{}, err
	}
	entries, parseErr := gemarapkg.ParseMappingEntries(content, mid, src, tgt, m.Framework)
	if parseErr != nil {
		slog.Warn("mapping parse failed", "mapping_id", mid, "error", parseErr)
	} else if len(entries) > 0 {
		if err := ms.InsertMappingEntries(ctx, entries); err != nil {
			slog.Warn("insert mapping entries failed", "mapping_id", mid, "error", err)
		}
	}
	return OciImportedArtifact{Type: "MappingDocument", ID: mid, Name: m.Framework}, nil
}

// ImportStores groups store interfaces needed by StoreCatalogFromContent.
type ImportStores struct {
	Catalogs CatalogStore
	Controls ControlStore
	Threats  ThreatStore
	Risks    RiskStore
	Guidance GuidanceStore
}

// StoreCatalogFromContent stores a catalog artifact and parses structured rows.
func StoreCatalogFromContent(ctx context.Context, s ImportStores, artType, content string) (OciImportedArtifact, error) {
	_, title := DetectCatalogType(content)
	catalogID := DetectCatalogID(content)
	if catalogID == "" {
		catalogID = uuid.NewString()
	}
	if s.Catalogs != nil {
		if err := s.Catalogs.InsertCatalog(ctx, Catalog{
			CatalogID:   catalogID,
			CatalogType: artType,
			Title:       title,
			Content:     content,
		}); err != nil {
			return OciImportedArtifact{}, err
		}
	}
	ParseCatalogStructuredRows(ctx, artType, content, catalogID, "", s.Controls, s.Threats, s.Risks, s.Guidance)
	return OciImportedArtifact{Type: artType, ID: catalogID, Name: title}, nil
}

// StoreArtifactFile routes a bundle file to the appropriate store function.
func StoreArtifactFile(ctx context.Context, ps PolicyStore, ctrlS ControlStore, ms MappingStore, is ImportStores, f gemarabundle.File) (OciImportedArtifact, error) {
	content := string(f.Data)
	detected, err := gemara.DetectType(f.Data)
	if err != nil {
		return OciImportedArtifact{}, err
	}
	artType := detected.String()

	switch artType {
	case "Policy":
		return StorePolicyFromContent(ctx, ps, ctrlS, content)
	case "MappingDocument":
		return StoreMappingFromContent(ctx, ms, content)
	case "ControlCatalog", "ThreatCatalog", "RiskCatalog", "GuidanceCatalog":
		return StoreCatalogFromContent(ctx, is, artType, content)
	default:
		slog.Debug("skipping unsupported artifact type", "type", artType, "name", f.Name)
		return OciImportedArtifact{Type: artType, ID: "", Name: f.Name}, nil
	}
}

// NormalizeSlice returns an empty slice if the input is nil.
// This prevents nil slices from being passed as NULL to PostgreSQL
// which would violate NOT NULL constraints even when DEFAULT is set.
func NormalizeSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ExtractPolicyCriteria parses a policy's criteria section and inserts
// the resulting controls and assessment requirements. Returns the number
// of controls inserted. Safe to call on every import (uses upsert).
func ExtractPolicyCriteria(ctx context.Context, policyID, content string, ctrlS ControlStore) (int, error) {
	type parsedCriteria struct {
		Criteria []struct {
			ID                     string `yaml:"id"`
			Title                  string `yaml:"title"`
			Description            string `yaml:"description"`
			CatalogRef             string `yaml:"catalog-ref"`
			AssessmentRequirements []struct {
				ID          string `yaml:"id"`
				Description string `yaml:"description"`
			} `yaml:"assessment-requirements"`
		} `yaml:"criteria"`
	}

	var pol parsedCriteria
	if err := gemarapkg.UnmarshalYAML([]byte(content), &pol); err != nil {
		return 0, fmt.Errorf("parse policy criteria: %w", err)
	}
	if len(pol.Criteria) == 0 {
		return 0, nil
	}

	catalogID := policyID
	var controls []gemarapkg.ControlRow
	var reqs []gemarapkg.AssessmentRequirementRow

	for _, c := range pol.Criteria {
		controls = append(controls, gemarapkg.ControlRow{
			CatalogID: catalogID,
			ControlID: c.ID,
			Title:     c.Title,
			Objective: c.Description,
			State:     "Active",
			PolicyID:  policyID,
		})
		for _, ar := range c.AssessmentRequirements {
			reqs = append(reqs, gemarapkg.AssessmentRequirementRow{
				CatalogID:     catalogID,
				ControlID:     c.ID,
				RequirementID: ar.ID,
				Text:          ar.Description,
				State:         "Active",
			})
		}
	}

	if len(controls) > 0 {
		if err := ctrlS.InsertControls(ctx, controls); err != nil {
			return 0, fmt.Errorf("insert controls: %w", err)
		}
	}
	if len(reqs) > 0 {
		if err := ctrlS.InsertAssessmentRequirements(ctx, reqs); err != nil {
			slog.Warn("policy criteria ARs insert failed", "policy_id", policyID, "error", err)
		}
	}
	slog.Info("policy criteria extracted", "policy_id", policyID, "controls", len(controls), "requirements", len(reqs))
	return len(controls), nil
}
