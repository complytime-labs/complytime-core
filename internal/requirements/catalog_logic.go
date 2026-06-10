// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	gemarapkg "github.com/complytime-labs/complytime-core/internal/gemara"
)

// ParseCatalogStructuredRows parses a catalog and inserts structured rows
// into the appropriate store.
func ParseCatalogStructuredRows(
	ctx context.Context, catalogType, content, catalogID, policyID string,
	ctrlS ControlStore, threatS ThreatStore, riskS RiskStore, guidanceS GuidanceStore,
) {
	switch catalogType {
	case "ControlCatalog":
		if ctrlS == nil {
			return
		}
		controls, reqs, threats, err := gemarapkg.ParseControlCatalog(ctx, content, catalogID, policyID)
		if err != nil {
			slog.Warn("control catalog parse failed, structured rows skipped", "catalog_id", catalogID, "error", err)
			return
		}
		if len(controls) > 0 {
			if err := ctrlS.InsertControls(ctx, controls); err != nil {
				slog.Warn("insert controls failed", "catalog_id", catalogID, "error", err)
			}
		}
		if len(reqs) > 0 {
			if err := ctrlS.InsertAssessmentRequirements(ctx, reqs); err != nil {
				slog.Warn("insert assessment requirements failed", "catalog_id", catalogID, "error", err)
			}
		}
		if len(threats) > 0 {
			if err := ctrlS.InsertControlThreats(ctx, threats); err != nil {
				slog.Warn("insert control threats failed", "catalog_id", catalogID, "error", err)
			}
		}
		slog.Info("control catalog indexed", "catalog_id", catalogID, "controls", len(controls), "requirements", len(reqs), "control_threats", len(threats))

	case "ThreatCatalog":
		if threatS == nil {
			return
		}
		rows, err := gemarapkg.ParseThreatCatalog(ctx, content, catalogID, policyID)
		if err != nil {
			slog.Warn("threat catalog parse failed, structured rows skipped", "catalog_id", catalogID, "error", err)
			return
		}
		if len(rows) > 0 {
			if err := threatS.InsertThreats(ctx, rows); err != nil {
				slog.Warn("insert threats failed", "catalog_id", catalogID, "error", err)
			}
		}
		slog.Info("threat catalog indexed", "catalog_id", catalogID, "threats", len(rows))

	case "RiskCatalog":
		if riskS == nil {
			return
		}
		riskRows, linkRows, err := gemarapkg.ParseRiskCatalog(ctx, content, catalogID, policyID)
		if err != nil {
			slog.Warn("risk catalog parse failed, structured rows skipped", "catalog_id", catalogID, "error", err)
			return
		}
		if len(riskRows) > 0 {
			if err := riskS.InsertRisks(ctx, riskRows); err != nil {
				slog.Warn("insert risks failed", "catalog_id", catalogID, "error", err)
			}
		}
		if len(linkRows) > 0 {
			if err := riskS.InsertRiskThreats(ctx, linkRows); err != nil {
				slog.Warn("insert risk threats failed", "catalog_id", catalogID, "error", err)
			}
		}
		slog.Info("risk catalog indexed", "catalog_id", catalogID, "risks", len(riskRows), "risk_threats", len(linkRows))

	case "GuidanceCatalog":
		if guidanceS == nil {
			return
		}
		entries, err := gemarapkg.ParseGuidanceCatalog(ctx, content, catalogID)
		if err != nil {
			slog.Warn("guidance catalog parse failed, structured rows skipped", "catalog_id", catalogID, "error", err)
			return
		}
		if len(entries) > 0 {
			if err := guidanceS.InsertGuidanceEntries(ctx, entries); err != nil {
				slog.Warn("insert guidance entries failed", "catalog_id", catalogID, "error", err)
			}
		}
		slog.Info("guidance catalog indexed", "catalog_id", catalogID, "guidelines", len(entries))
	}
}

// DetectCatalogType detects the catalog type from content.
func DetectCatalogType(content string) (catalogType, title string) {
	var meta struct {
		Title    string `json:"title" yaml:"title"`
		Metadata struct {
			Type string `json:"type" yaml:"type"`
		} `json:"metadata" yaml:"metadata"`
	}
	trim := strings.TrimSpace(content)
	var err error
	if strings.HasPrefix(trim, "{") {
		err = json.Unmarshal([]byte(trim), &meta)
	} else {
		err = gemarapkg.UnmarshalYAML([]byte(content), &meta)
	}
	if err != nil {
		return "", ""
	}
	switch meta.Metadata.Type {
	case "ControlCatalog", "ThreatCatalog", "RiskCatalog", "GuidanceCatalog":
		return meta.Metadata.Type, meta.Title
	default:
		return "", ""
	}
}

// DetectCatalogID extracts the catalog ID from content metadata.
func DetectCatalogID(content string) string {
	var meta struct {
		Metadata struct {
			ID string `json:"id" yaml:"id"`
		} `json:"metadata" yaml:"metadata"`
	}
	trim := strings.TrimSpace(content)
	var err error
	if strings.HasPrefix(trim, "{") {
		err = json.Unmarshal([]byte(trim), &meta)
	} else {
		err = gemarapkg.UnmarshalYAML([]byte(content), &meta)
	}
	if err != nil {
		return ""
	}
	return meta.Metadata.ID
}
