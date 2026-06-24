// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// MapRouteAction maps HTTP method and path to a Cedar action entity UID.
// Returns false if the route is not recognized.
func MapRouteAction(method, path string) (cedar.EntityUID, bool) {
	switch {
	case method == "GET" && path == "/checkpoint":
		return cedar.NewEntityUID("Action", "read:checkpoint"), true
	case method == "GET" && strings.HasPrefix(path, "/log/witnessed/"):
		return cedar.NewEntityUID("Action", "read:checkpoint"), true
	case method == "GET" && strings.HasPrefix(path, "/tile/"):
		return cedar.NewEntityUID("Action", "read:entries"), true
	case method == "GET" && path == "/api/system-info":
		return cedar.NewEntityUID("Action", "read:status"), true
	case method == "GET" && path == "/api/config":
		return cedar.NewEntityUID("Action", "read:status"), true
	case method == "GET" && strings.HasPrefix(path, "/api/ingest/jobs/"):
		return cedar.NewEntityUID("Action", "read:status"), true
	case method == "POST" && path == "/api/ingest":
		return cedar.NewEntityUID("Action", "publish"), true
	case method == "POST" && path == "/api/import":
		return cedar.NewEntityUID("Action", "publish"), true
	default:
		return cedar.EntityUID{}, false
	}
}
