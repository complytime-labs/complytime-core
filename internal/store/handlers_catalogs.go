// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func registerCatalogRoutes(g *echo.Group, s Stores) {
	g.GET("/catalogs", listCatalogsHandler(s.Catalogs))
	g.POST("/catalogs/import", importCatalogHandler(s.Catalogs, s.Controls, s.Threats, s.Risks, s.Guidance))
}

func listCatalogsHandler(cs requirements.CatalogStore) echo.HandlerFunc {
	type catalogLite struct {
		CatalogID   string    `json:"catalog_id"`
		CatalogType string    `json:"catalog_type"`
		Title       string    `json:"title"`
		PolicyID    string    `json:"policy_id,omitempty"`
		ImportedAt  time.Time `json:"imported_at"`
	}
	return func(c echo.Context) error {
		if cs == nil {
			return c.JSON(http.StatusOK, []catalogLite{})
		}
		rows, err := cs.ListCatalogs(c.Request().Context())
		if err != nil {
			slog.Error("list catalogs failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		filter := c.QueryParam("type")
		out := make([]catalogLite, 0, len(rows))
		for _, row := range rows {
			if filter != "" && row.CatalogType != filter {
				continue
			}
			out = append(out, catalogLite{
				CatalogID:   row.CatalogID,
				CatalogType: row.CatalogType,
				Title:       row.Title,
				PolicyID:    row.PolicyID,
				ImportedAt:  row.ImportedAt,
			})
		}
		return c.JSON(http.StatusOK, out)
	}
}

func importCatalogHandler(
	cs requirements.CatalogStore, ctrlS requirements.ControlStore, threatS requirements.ThreatStore, riskS requirements.RiskStore, guidanceS requirements.GuidanceStore,
) echo.HandlerFunc {
	type importReq struct {
		CatalogID string `json:"catalog_id"`
		PolicyID  string `json:"policy_id"`
		Content   string `json:"content"`
	}
	return func(c echo.Context) error {
		var req importReq
		if err := c.Bind(&req); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid json")
		}
		if req.Content == "" {
			return jsonError(c, http.StatusBadRequest, "content required")
		}

		catalogType, title := requirements.DetectCatalogType(req.Content)
		if catalogType == "" {
			return jsonError(c, http.StatusBadRequest,
				"could not detect catalog type from content (expected ControlCatalog, ThreatCatalog, RiskCatalog, or GuidanceCatalog)")
		}

		catalogID := req.CatalogID
		if catalogID == "" {
			catalogID = requirements.DetectCatalogID(req.Content)
		}

		if cs != nil {
			if err := cs.InsertCatalog(c.Request().Context(), requirements.Catalog{
				CatalogID:   catalogID,
				CatalogType: catalogType,
				Title:       title,
				Content:     req.Content,
				PolicyID:    req.PolicyID,
			}); err != nil {
				if errors.Is(err, ErrConflict) {
					return jsonError(c, http.StatusConflict, "catalog already exists")
				}
				slog.Error("insert catalog failed", "error", err)
				return jsonError(c, http.StatusInternalServerError, "insert failed")
			}
		}

		requirements.ParseCatalogStructuredRows(
			c.Request().Context(), catalogType, req.Content, catalogID, req.PolicyID, ctrlS, threatS, riskS, guidanceS,
		)

		return c.JSON(http.StatusCreated, map[string]string{
			"status":       "imported",
			"catalog_id":   catalogID,
			"catalog_type": catalogType,
		})
	}
}
