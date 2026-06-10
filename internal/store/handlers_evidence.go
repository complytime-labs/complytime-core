// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/evidence"
)

func registerEvidenceRoutes(g *echo.Group, s Stores) {
	g.GET("/evidence", queryEvidenceHandler(s.Evidence))
}

func registerCertificationsRoutes(g *echo.Group, s Stores) {
	if s.Certifications != nil {
		g.GET("/certifications", queryCertificationsHandler(s.Certifications))
	}
}

func queryCertificationsHandler(s evidence.CertificationStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		evidenceID := c.QueryParam("evidence_id")
		if evidenceID == "" {
			return jsonError(c, http.StatusBadRequest, "evidence_id required")
		}
		rows, err := s.QueryCertifications(c.Request().Context(), evidenceID)
		if err != nil {
			slog.Error("query certifications failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		if rows == nil {
			rows = []evidence.CertificationRow{}
		}
		return c.JSON(http.StatusOK, rows)
	}
}

func queryEvidenceHandler(s evidence.EvidenceStore) echo.HandlerFunc {
	const maxPolicyIDs = 50

	return func(c echo.Context) error {
		f := evidence.EvidenceFilter{
			ControlID:     c.QueryParam("control_id"),
			TargetName:    c.QueryParam("target_name"),
			TargetType:    c.QueryParam("target_type"),
			TargetEnv:     c.QueryParam("target_env"),
			EngineVersion: c.QueryParam("engine_version"),
			Owner:         c.QueryParam("owner"),
		}
		if policyID := c.QueryParam("policy_id"); policyID != "" {
			f.PolicyIDs = []string{policyID}
		}
		if pids := c.QueryParam("policy_ids"); pids != "" {
			for _, p := range strings.Split(pids, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					f.PolicyIDs = append(f.PolicyIDs, p)
				}
			}
		}
		if len(f.PolicyIDs) > maxPolicyIDs {
			return jsonError(c, http.StatusBadRequest, fmt.Sprintf("too many policy_ids (max %d)", maxPolicyIDs))
		}
		if v := c.QueryParam("start"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.Start = t
			} else if t, err := time.Parse("2006-01-02", v); err == nil {
				f.Start = t
			}
		}
		if v := c.QueryParam("end"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.End = t
			} else if t, err := time.Parse("2006-01-02", v); err == nil {
				f.End = t
			}
		}
		if v := c.QueryParam("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				f.Limit = n
			}
		}
		if v := c.QueryParam("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				f.Offset = n
			}
		}
		f.Limit = consts.ClampLimit(f.Limit)

		records, err := s.QueryEvidence(c.Request().Context(), f)
		if err != nil {
			slog.Error("query evidence failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		if records == nil {
			records = []evidence.EvidenceRecord{}
		}
		return c.JSON(http.StatusOK, records)
	}
}
