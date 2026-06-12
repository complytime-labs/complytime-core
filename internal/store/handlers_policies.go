// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/complytime-labs/complytime-core/internal/posture"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func registerPolicyRoutes(g *echo.Group, s Stores) {
	g.GET("/policies", listPoliciesHandler(s.Policies))
	g.GET("/policies/:id", getPolicyHandler(s.Policies, s.Mappings))
	if s.Coverage != nil {
		g.GET("/policies/:id/coverage", coverageHandler(s.Coverage, s.Policies))
	}
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

func coverageHandler(cs posture.CoverageStore, ps requirements.PolicyStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		policyID := c.Param("id")
		if policyID == "" {
			return jsonError(c, http.StatusBadRequest, "missing policy id")
		}

		f := posture.CoverageFilter{PolicyID: policyID}
		f.TargetID = c.QueryParam("target_id")

		if v := c.QueryParam("since"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.Since = t
			} else if t, err := time.Parse("2006-01-02", v); err == nil {
				f.Since = t
			}
		}
		if v := c.QueryParam("max_age"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				f.MaxAge = d
			}
		}

		if ps != nil {
			if pol, err := ps.GetPolicy(c.Request().Context(), policyID); err == nil && pol.Content != "" {
				f.Freshness = gemara.ExtractAdherenceFrequencies(pol.Content)
			}
		}

		result, err := cs.QueryCoverage(c.Request().Context(), f)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return jsonError(c, http.StatusNotFound, "no requirements found for this policy")
			}
			slog.Error("query coverage failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}

		return c.JSON(http.StatusOK, result)
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
