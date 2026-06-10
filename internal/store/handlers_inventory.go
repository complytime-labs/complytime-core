// SPDX-License-Identifier: Apache-2.0

package store

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/posture"
)

func registerInventoryRoutes(g *echo.Group, s Stores) {
	if s.Inventory != nil {
		g.GET("/inventory", listInventoryHandler(s.Inventory))
	}
}

func listInventoryHandler(s posture.InventoryStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var f posture.InventoryFilter
		if err := c.Bind(&f); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid query")
		}
		if f.ProgramID != "" {
			if _, err := uuid.Parse(f.ProgramID); err != nil {
				return jsonError(c, http.StatusBadRequest, "invalid program_id")
			}
		}
		items, err := s.ListInventory(c.Request().Context(), f)
		if err != nil {
			slog.Error("list inventory failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		if items == nil {
			items = []posture.InventoryItem{}
		}
		return c.JSON(http.StatusOK, items)
	}
}
