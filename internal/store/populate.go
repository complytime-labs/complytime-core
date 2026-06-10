// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"log/slog"

	sdk "github.com/gemaraproj/go-gemara"
	goyaml "github.com/goccy/go-yaml"

	gemarapkg "github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// PopulateMappingEntries backfills the mapping_entries table from existing
// mapping_documents. Skips documents that already have entries. Safe to call
// on every startup.
func PopulateMappingEntries(ctx context.Context, s requirements.MappingStore) error {
	docs, err := s.ListAllMappings(ctx)
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return nil
	}

	var totalInserted int
	for _, doc := range docs {
		count, err := s.CountMappingEntries(ctx, doc.MappingID)
		if err != nil {
			slog.Warn("count mapping entries failed, skipping", "mapping_id", doc.MappingID, "error", err)
			continue
		}
		if count > 0 {
			continue
		}

		entries, parseErr := gemarapkg.ParseMappingEntries(doc.Content, doc.MappingID, doc.SourceCatalogID, doc.TargetCatalogID, doc.Framework)
		if parseErr != nil {
			slog.Warn("retroactive parse failed, skipping", "mapping_id", doc.MappingID, "error", parseErr)
			continue
		}
		if len(entries) == 0 {
			continue
		}

		if err := s.InsertMappingEntries(ctx, entries); err != nil {
			slog.Warn("retroactive insert failed", "mapping_id", doc.MappingID, "error", err)
			continue
		}
		totalInserted += len(entries)
	}

	if totalInserted > 0 {
		slog.Info("mapping entries backfilled", "entries", totalInserted, "documents", len(docs))
	}
	return nil
}

// PopulateControls backfills controls, assessment_requirements, and
// control_threats from stored ControlCatalog content. Safe to call on startup.
func PopulateControls(ctx context.Context, cs requirements.CatalogStore, ctrlS requirements.ControlStore) error {
	catalogs, err := cs.ListCatalogs(ctx)
	if err != nil {
		return err
	}

	var totalControls int
	for _, cat := range catalogs {
		if cat.CatalogType != "ControlCatalog" {
			continue
		}
		count, err := ctrlS.CountControls(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("count controls failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}
		if count > 0 {
			continue
		}

		full, err := cs.GetCatalog(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("get catalog content failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}

		controls, reqs, threats, parseErr := gemarapkg.ParseControlCatalog(ctx, full.Content, cat.CatalogID, cat.PolicyID)
		if parseErr != nil {
			slog.Warn("retroactive control catalog parse failed, skipping", "catalog_id", cat.CatalogID, "error", parseErr)
			continue
		}
		if len(controls) > 0 {
			if err := ctrlS.InsertControls(ctx, controls); err != nil {
				slog.Warn("retroactive controls insert failed", "catalog_id", cat.CatalogID, "error", err)
				continue
			}
		}
		if len(reqs) > 0 {
			if err := ctrlS.InsertAssessmentRequirements(ctx, reqs); err != nil {
				slog.Warn("retroactive assessment requirements insert failed", "catalog_id", cat.CatalogID, "error", err)
			}
		}
		if len(threats) > 0 {
			if err := ctrlS.InsertControlThreats(ctx, threats); err != nil {
				slog.Warn("retroactive control threats insert failed", "catalog_id", cat.CatalogID, "error", err)
			}
		}
		totalControls += len(controls)
	}

	if totalControls > 0 {
		slog.Info("controls backfilled", "controls", totalControls)
	}
	return nil
}

// PopulateThreats backfills the threats table from stored ThreatCatalog
// content. Safe to call on startup.
func PopulateThreats(ctx context.Context, cs requirements.CatalogStore, threatS requirements.ThreatStore) error {
	catalogs, err := cs.ListCatalogs(ctx)
	if err != nil {
		return err
	}

	var totalThreats int
	for _, cat := range catalogs {
		if cat.CatalogType != "ThreatCatalog" {
			continue
		}
		count, err := threatS.CountThreats(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("count threats failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}
		if count > 0 {
			continue
		}

		full, err := cs.GetCatalog(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("get catalog content failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}

		rows, parseErr := gemarapkg.ParseThreatCatalog(ctx, full.Content, cat.CatalogID, cat.PolicyID)
		if parseErr != nil {
			slog.Warn("retroactive threat catalog parse failed, skipping", "catalog_id", cat.CatalogID, "error", parseErr)
			continue
		}
		if len(rows) > 0 {
			if err := threatS.InsertThreats(ctx, rows); err != nil {
				slog.Warn("retroactive threats insert failed", "catalog_id", cat.CatalogID, "error", err)
				continue
			}
		}
		totalThreats += len(rows)
	}

	if totalThreats > 0 {
		slog.Info("threats backfilled", "threats", totalThreats)
	}
	return nil
}

// PopulateRisks backfills risks and risk_threats from stored RiskCatalog
// content. Safe to call on startup.
func PopulateRisks(ctx context.Context, cs requirements.CatalogStore, riskS requirements.RiskStore) error {
	catalogs, err := cs.ListCatalogs(ctx)
	if err != nil {
		return err
	}

	var totalRisks int
	for _, cat := range catalogs {
		if cat.CatalogType != "RiskCatalog" {
			continue
		}
		count, err := riskS.CountRisks(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("count risks failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}
		if count > 0 {
			continue
		}

		full, err := cs.GetCatalog(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("get catalog content failed, skipping", "catalog_id", cat.CatalogID, "error", err)
			continue
		}

		riskRows, linkRows, parseErr := gemarapkg.ParseRiskCatalog(ctx, full.Content, cat.CatalogID, cat.PolicyID)
		if parseErr != nil {
			slog.Warn("retroactive risk catalog parse failed, skipping", "catalog_id", cat.CatalogID, "error", parseErr)
			continue
		}
		if len(riskRows) > 0 {
			if err := riskS.InsertRisks(ctx, riskRows); err != nil {
				slog.Warn("retroactive risks insert failed", "catalog_id", cat.CatalogID, "error", err)
				continue
			}
		}
		if len(linkRows) > 0 {
			if err := riskS.InsertRiskThreats(ctx, linkRows); err != nil {
				slog.Warn("retroactive risk threats insert failed", "catalog_id", cat.CatalogID, "error", err)
			}
		}
		totalRisks += len(riskRows)
	}

	if totalRisks > 0 {
		slog.Info("risks backfilled", "risks", totalRisks)
	}
	return nil
}

// PopulateEffectiveControls resolves each stored policy's catalog imports
// against the catalogs table, applies policy-level overlays (exclusions,
// AR modifications), and inserts the effective controls. Safe on every startup.
func PopulateEffectiveControls(ctx context.Context, ps requirements.PolicyStore, cs requirements.CatalogStore, ctrlS requirements.ControlStore) error {
	policies, err := ps.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}

	catalogs, err := cs.ListCatalogs(ctx)
	if err != nil {
		return fmt.Errorf("list catalogs: %w", err)
	}

	var sdkCatalogs []sdk.ControlCatalog
	for _, cat := range catalogs {
		if cat.CatalogType != "ControlCatalog" {
			continue
		}
		full, err := cs.GetCatalog(ctx, cat.CatalogID)
		if err != nil {
			slog.Warn("load catalog for effective resolution", "catalog_id", cat.CatalogID, "error", err)
			continue
		}
		var cc sdk.ControlCatalog
		if err := goyaml.Unmarshal([]byte(full.Content), &cc); err != nil {
			slog.Warn("parse catalog for effective resolution", "catalog_id", cat.CatalogID, "error", err)
			continue
		}
		sdkCatalogs = append(sdkCatalogs, cc)
	}

	if len(sdkCatalogs) == 0 {
		return nil
	}

	var totalControls int
	for _, p := range policies {
		var pol sdk.Policy
		if err := goyaml.Unmarshal([]byte(p.Content), &pol); err != nil {
			slog.Warn("parse policy for effective resolution", "policy_id", p.PolicyID, "error", err)
			continue
		}

		if len(pol.Imports.Catalogs) == 0 {
			continue
		}

		effective, err := gemarapkg.ResolveEffectiveControls(pol, sdkCatalogs)
		if err != nil {
			slog.Warn("effective control resolution failed", "policy_id", p.PolicyID, "error", err)
			continue
		}

		controls, reqs, threats := gemarapkg.ExtractControlRows(effective, p.PolicyID)
		if len(controls) == 0 {
			continue
		}

		first := controls[0].CatalogID
		count, _ := ctrlS.CountControls(ctx, first)
		if count > 0 {
			continue
		}

		if err := ctrlS.InsertControls(ctx, controls); err != nil {
			slog.Warn("effective controls insert failed", "policy_id", p.PolicyID, "error", err)
			continue
		}
		if len(reqs) > 0 {
			if err := ctrlS.InsertAssessmentRequirements(ctx, reqs); err != nil {
				slog.Warn("effective ARs insert failed", "policy_id", p.PolicyID, "error", err)
			}
		}
		if len(threats) > 0 {
			if err := ctrlS.InsertControlThreats(ctx, threats); err != nil {
				slog.Warn("effective threats insert failed", "policy_id", p.PolicyID, "error", err)
			}
		}
		totalControls += len(controls)
		slog.Info("effective controls resolved", "policy_id", p.PolicyID, "controls", len(controls), "requirements", len(reqs))
	}

	if totalControls > 0 {
		slog.Info("effective controls backfilled", "total_controls", totalControls)
	}
	return nil
}

// PopulatePolicyCriteria extracts criteria and assessment-requirements
// directly from each policy's YAML content. Safe to call on every startup.
func PopulatePolicyCriteria(ctx context.Context, ps requirements.PolicyStore, ctrlS requirements.ControlStore) error {
	policies, err := ps.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}

	var totalControls int
	for _, p := range policies {
		count, _ := ctrlS.CountControls(ctx, p.PolicyID)
		if count > 0 {
			continue
		}
		full, err := ps.GetPolicy(ctx, p.PolicyID)
		if err != nil {
			slog.Warn("get policy content for criteria", "policy_id", p.PolicyID, "error", err)
			continue
		}
		n, extractErr := requirements.ExtractPolicyCriteria(ctx, p.PolicyID, full.Content, ctrlS)
		if extractErr != nil {
			slog.Warn("policy criteria extraction failed", "policy_id", p.PolicyID, "error", extractErr)
			continue
		}
		totalControls += n
	}
	if totalControls > 0 {
		slog.Info("policy criteria backfilled", "total_controls", totalControls)
	}
	return nil
}

// ExtractPolicyCriteria delegates to requirements.ExtractPolicyCriteria.
func ExtractPolicyCriteria(ctx context.Context, policyID, content string, ctrlS requirements.ControlStore) (int, error) {
	return requirements.ExtractPolicyCriteria(ctx, policyID, content, ctrlS)
}
