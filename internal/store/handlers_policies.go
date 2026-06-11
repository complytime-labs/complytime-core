// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func registerPolicyRoutes(g *echo.Group, s Stores) {
	g.GET("/policies", listPoliciesHandler(s.Policies))
	g.GET("/policies/:id", getPolicyHandler(s.Policies, s.Mappings))
	registerImportRoute(g, s)
}

func listPoliciesHandler(s requirements.PolicyStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		policies, err := s.ListPolicies(c.Request().Context())
		if err != nil {
			slog.Error("list policies failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "internal error")
		}
		if policies == nil {
			policies = []requirements.Policy{}
		}
		return c.JSON(http.StatusOK, policies)
	}
}

func getPolicyHandler(ps requirements.PolicyStore, ms requirements.MappingStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")
		if id == "" {
			return jsonError(c, http.StatusBadRequest, "missing policy id")
		}
		p, err := ps.GetPolicy(c.Request().Context(), id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return jsonError(c, http.StatusNotFound, "not found")
			}
			slog.Error("get policy failed", "error", err, "id", id)
			return jsonError(c, http.StatusInternalServerError, "internal server error")
		}
		mappings, _ := ms.ListMappings(c.Request().Context(), id)
		if mappings == nil {
			mappings = []requirements.MappingDocument{}
		}
		resp := struct {
			Policy   *requirements.Policy           `json:"policy"`
			Mappings []requirements.MappingDocument `json:"mappings"`
		}{Policy: p, Mappings: mappings}
		return c.JSON(http.StatusOK, resp)
	}
}
