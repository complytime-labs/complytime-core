// SPDX-License-Identifier: Apache-2.0

package store

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

func registerEntryRoute(g *echo.Group, s Stores) {
	if s.TesseraReader != nil {
		g.GET("/entry/:index", EntryHandler(s.TesseraReader))
	}
}

// EntryHandler returns a handler that reads individual Tessera log entries by index.
func EntryHandler(reader TesseraReader) echo.HandlerFunc {
	return func(c echo.Context) error {
		indexStr := c.Param("index")
		index, err := strconv.ParseUint(indexStr, 10, 64)
		if err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid index — expected unsigned integer")
		}

		data, err := reader.Read(c.Request().Context(), index)
		if err != nil {
			if strings.Contains(err.Error(), "not yet integrated") {
				return jsonError(c, http.StatusNotFound, "entry not found")
			}
			return jsonError(c, http.StatusNotFound, "entry not found")
		}

		contentType := "application/x-yaml"
		if len(data) > 0 && data[0] == '{' {
			contentType = "application/json"
		}

		return c.Blob(http.StatusOK, contentType, data)
	}
}
