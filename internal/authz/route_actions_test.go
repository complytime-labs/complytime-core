// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestMapRouteAction_AllKnownRoutes(t *testing.T) {
	routes := []struct {
		method     string
		path       string
		wantAction string
	}{
		{"GET", "/checkpoint", "read:checkpoint"},
		{"GET", "/log/witnessed/0", "read:checkpoint"},
		{"GET", "/tile/entries/000", "read:entries"},
		{"GET", "/tile/0/000", "read:entries"},
		{"GET", "/api/system-info", "read:status"},
		{"GET", "/api/config", "read:status"},
		{"GET", "/api/ingest/jobs/abc-123", "read:status"},
		{"POST", "/api/ingest", "publish"},
		{"POST", "/api/import", "publish"},
		{"POST", "/api/admin/targets", "admin:register-target"},
	}

	for _, tt := range routes {
		action, ok := MapRouteAction(tt.method, tt.path)
		if !ok {
			t.Errorf("MapRouteAction(%s, %s) returned false — route not mapped", tt.method, tt.path)
			continue
		}
		got := string(action.ID)
		if got != tt.wantAction {
			t.Errorf("MapRouteAction(%s, %s) = %q, want %q", tt.method, tt.path, got, tt.wantAction)
		}
	}
}

func TestMapRouteAction_UnknownRoutes(t *testing.T) {
	unknowns := []struct {
		method string
		path   string
	}{
		{"DELETE", "/api/ingest"},
		{"GET", "/api/unknown"},
		{"POST", "/api/unknown"},
		{"PUT", "/api/ingest"},
	}

	for _, tt := range unknowns {
		_, ok := MapRouteAction(tt.method, tt.path)
		if ok {
			t.Errorf("MapRouteAction(%s, %s) should return false for unknown route", tt.method, tt.path)
		}
	}
}
