// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gemara "github.com/gemaraproj/go-gemara"
	gemarabundle "github.com/gemaraproj/go-gemara/bundle"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/events"
	gemarapkg "github.com/complytime-labs/complytime-core/internal/gemara"
)

const maxUnifiedImportBytes = 10 << 20

func registerImportRoute(g *echo.Group, s Stores) {
	g.POST("/import", importArtifactHandler(s))
}

// importArtifactHandler accepts OCI bundle references only.
// Raw artifact ingestion goes through POST /api/ingest (async via NATS).
// See ADR #0034 — Unified Ingest Pipeline.
func importArtifactHandler(s Stores) echo.HandlerFunc {
	return func(c echo.Context) error {
		body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxUnifiedImportBytes))
		if err != nil {
			return jsonError(c, http.StatusBadRequest, "read body failed")
		}
		var probe struct {
			Reference string `json:"reference"`
		}
		if json.Unmarshal(body, &probe) != nil || strings.TrimSpace(probe.Reference) == "" {
			return jsonError(c, http.StatusBadRequest,
				"expected JSON body with \"reference\" field — "+
					"for raw YAML, use POST /api/ingest")
		}
		return ociImport(c, s, strings.TrimSpace(probe.Reference))
	}
}

// ── OCI reference import ────────────────────────────────────────────────────

type ociImportedArtifact struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type ociImportResponse struct {
	Imported []ociImportedArtifact `json:"imported"`
	Digest   string                `json:"digest,omitempty"`
}

func ociImport(c echo.Context, s Stores, ref string) error {
	if s.Registry == nil {
		return jsonError(c, http.StatusServiceUnavailable, "registry not configured")
	}

	repo, err := s.Registry.Repository(ref)
	if err != nil {
		return jsonError(c, http.StatusForbidden, err.Error())
	}

	ctx := c.Request().Context()
	bundle, err := gemarabundle.Unpack(ctx, repo, repo.Reference.Reference)
	if err != nil {
		slog.Error("oci import unpack failed", "reference", ref, "error", err)
		return jsonError(c, http.StatusBadGateway, "failed to pull bundle: "+err.Error())
	}

	bundleID := uuid.New().String()
	allFiles := append(bundle.Files, bundle.Imports...)

	if s.TesseraAppender == nil || s.IngestPublisher == nil {
		return ociImportLegacy(c, s, allFiles, bundle.Etag)
	}

	identity := events.PublisherIdentity{
		Sub:      "import:" + ref,
		Issuer:   "complytime-gateway",
		Type:     "import",
		Verified: true,
	}

	var imported []ociImportedArtifact
	for _, f := range allFiles {
		detected, err := gemara.DetectType(f.Data)
		if err != nil {
			slog.Warn("skip unrecognized artifact", "name", f.Name, "error", err)
			continue
		}

		logIndex, err := s.TesseraAppender.Add(ctx, f.Data)
		if err != nil {
			slog.Error("tessera append failed", "name", f.Name, "error", err)
			continue
		}

		jobID := uuid.New().String()
		s.IngestTracker.Create(jobID)

		ingestRef := events.IngestRef{
			JobID:             jobID,
			LogIndex:          logIndex,
			PublisherIdentity: identity,
			BundleID:          bundleID,
			OCIReference:      ref,
			Timestamp:         time.Now().UTC(),
		}
		if err := s.IngestPublisher.PublishIngest(ctx, ingestRef); err != nil {
			s.IngestTracker.Fail(jobID, fmt.Sprintf("publish failed: %v", err))
			slog.Error("jetstream publish failed", "name", f.Name, "error", err)
			continue
		}

		imported = append(imported, ociImportedArtifact{
			Type: detected.String(),
			Name: f.Name,
		})
	}

	return c.JSON(http.StatusAccepted, map[string]any{
		"bundle_id": bundleID,
		"status":    "processing",
		"digest":    bundle.Etag,
		"artifacts": len(imported),
	})
}

func ociImportLegacy(c echo.Context, s Stores, files []gemarabundle.File, etag string) error {
	var resp ociImportResponse
	resp.Digest = etag

	ctx := c.Request().Context()
	for _, f := range files {
		art, err := storeArtifactFile(ctx, s, f)
		if err != nil {
			slog.Warn("import artifact failed", "name", f.Name, "error", err)
			continue
		}
		resp.Imported = append(resp.Imported, art)
	}

	if len(resp.Imported) == 0 {
		return jsonError(c, http.StatusBadRequest, "bundle contained no importable artifacts")
	}

	return c.JSON(http.StatusCreated, resp)
}

// policyIngestOption carries Tessera provenance data for async-ingested policies.
type policyIngestOption struct {
	LogIndex uint64
	BundleID string
}

func storeArtifactFile(ctx context.Context, s Stores, f gemarabundle.File) (ociImportedArtifact, error) {
	content := string(f.Data)
	detected, err := gemara.DetectType(f.Data)
	if err != nil {
		return ociImportedArtifact{}, err
	}
	artType := detected.String()

	switch artType {
	case "Policy":
		return storePolicyFromContent(ctx, s.Policies, s.Controls, content)
	case "MappingDocument":
		return storeMappingFromContent(ctx, s.Mappings, content)
	case "ControlCatalog", "ThreatCatalog", "RiskCatalog", "GuidanceCatalog":
		return storeCatalogFromContent(ctx, s, artType, content)
	default:
		slog.Debug("skipping unsupported artifact type", "type", artType, "name", f.Name)
		return ociImportedArtifact{Type: artType, ID: "", Name: f.Name}, nil
	}
}

func storePolicyFromContent(ctx context.Context, ps PolicyStore, ctrlS ControlStore, content string, opts ...policyIngestOption) (ociImportedArtifact, error) {
	var pol gemara.Policy
	if err := gemarapkg.UnmarshalYAML([]byte(content), &pol); err != nil {
		return ociImportedArtifact{}, err
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
		Technologies: normalizeSlice(pol.Scope.In.Technologies),
		Geopolitical: normalizeSlice(pol.Scope.In.Geopolitical),
		Sensitivity:  normalizeSlice(pol.Scope.In.Sensitivity),
		Users:        normalizeSlice(pol.Scope.In.Users),
		Groups:       normalizeSlice(pol.Scope.In.Groups),
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
		return ociImportedArtifact{}, err
	}
	if ctrlS != nil {
		if _, err := ExtractPolicyCriteria(ctx, p.PolicyID, content, ctrlS); err != nil {
			slog.Warn("inline criteria extraction failed", "policy_id", p.PolicyID, "error", err)
		}
	}
	return ociImportedArtifact{Type: "Policy", ID: p.PolicyID, Name: title}, nil
}

func storeMappingFromContent(ctx context.Context, ms MappingStore, content string) (ociImportedArtifact, error) {
	var doc gemara.MappingDocument
	if err := gemarapkg.UnmarshalYAML([]byte(content), &doc); err != nil {
		return ociImportedArtifact{}, err
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
		return ociImportedArtifact{}, err
	}
	entries, parseErr := gemarapkg.ParseMappingEntries(content, mid, src, tgt, m.Framework)
	if parseErr != nil {
		slog.Warn("mapping parse failed", "mapping_id", mid, "error", parseErr)
	} else if len(entries) > 0 {
		if err := ms.InsertMappingEntries(ctx, entries); err != nil {
			slog.Warn("insert mapping entries failed", "mapping_id", mid, "error", err)
		}
	}
	return ociImportedArtifact{Type: "MappingDocument", ID: mid, Name: m.Framework}, nil
}

func storeCatalogFromContent(ctx context.Context, s Stores, artType, content string) (ociImportedArtifact, error) {
	_, title := detectCatalogType(content)
	catalogID := detectCatalogID(content)
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
			return ociImportedArtifact{}, err
		}
	}
	parseCatalogStructuredRows(ctx, artType, content, catalogID, "", s.Controls, s.Threats, s.Risks, s.Guidance)
	return ociImportedArtifact{Type: artType, ID: catalogID, Name: title}, nil
}

// rawBodyImport, importPolicyFromArtifactBody, importMappingFromArtifactBody,
// importCatalogFromArtifactBody removed — see ADR #0034. All raw artifact
// ingestion now flows through POST /api/ingest → NATS → IngestWorker.
