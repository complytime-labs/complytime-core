// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"strings"

	"github.com/cedar-policy/cedar-go"
)

type routeMapping struct {
	method string
	path   string
	prefix bool
	action string
}

var routeMappings = []routeMapping{
	{"GET", "/checkpoint", false, "read:checkpoint"},
	{"GET", "/log/witnessed/", true, "read:checkpoint"},
	{"GET", "/tile/", true, "read:entries"},
	{"GET", "/api/system-info", false, "read:status"},
	{"GET", "/api/config", false, "read:status"},
	{"GET", "/api/ingest/jobs/", true, "read:status"},
	{"POST", "/api/ingest", false, "publish"},
	{"POST", "/api/import", false, "publish"},
	{"POST", "/api/admin/targets", false, "admin:register-target"},
}

// MapRouteAction maps HTTP method and path to a Cedar action entity UID.
// Returns false if the route is not recognized.
func MapRouteAction(method, path string) (cedar.EntityUID, bool) {
	for _, m := range routeMappings {
		if m.method != method {
			continue
		}
		if m.prefix && strings.HasPrefix(path, m.path) {
			return cedar.NewEntityUID("Action", cedar.String(m.action)), true
		}
		if !m.prefix && path == m.path {
			return cedar.NewEntityUID("Action", cedar.String(m.action)), true
		}
	}
	return cedar.EntityUID{}, false
}
