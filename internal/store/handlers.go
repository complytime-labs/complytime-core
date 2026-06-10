// SPDX-License-Identifier: Apache-2.0

package store

import (
	"github.com/labstack/echo/v4"
)

func jsonError(c echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
}

// Register mounts all public store API endpoints on g (typically e.Group("/api")).
// Internal (agent-only) endpoints are registered via RegisterInternal.
func Register(g *echo.Group, s Stores) {
	registerPolicyRoutes(g, s)
	registerIngestRoutes(g, s)
	registerEvidenceRoutes(g, s)
	registerInventoryRoutes(g, s)
	registerCertificationsRoutes(g, s)
	registerAuditRoutes(g, s)
	registerCatalogRoutes(g, s)
	registerPostureAndRequirementRoutes(g, s)
	registerDraftAuditRoutes(g, s)
	registerThreatAndRiskRoutes(g, s)
	registerTargetRoutes(g, s)
}
