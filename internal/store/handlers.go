// SPDX-License-Identifier: Apache-2.0

package store

import (
	"github.com/labstack/echo/v4"
)

func jsonError(c echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
}

// Register mounts all public store API endpoints on g (typically e.Group("/api")).
func Register(g *echo.Group, s Stores) {
	registerIngestRoutes(g, s)
	registerImportRoute(g, s)
	registerEntryRoute(g, s)
}
