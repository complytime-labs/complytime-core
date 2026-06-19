// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"github.com/labstack/echo/v4"
)

// newTestEchoServer creates an Echo instance for E2E testing.
func newTestEchoServer() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	return e
}
