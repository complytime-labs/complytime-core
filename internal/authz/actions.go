package authz

import (
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// Cedar action entity UIDs
var (
	ActionPublishArtifact          = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("publish:artifact"))
	ActionRequestRegistration      = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("admin:request-registration"))
	ActionRequestTrustModification = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("admin:request-trust-modification"))
	ActionReadEvidence             = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("read:evidence"))
	ActionQueryEvidence            = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("query:evidence"))
)

// routeMapping maps HTTP method + path patterns to Cedar actions
type routeMapping struct {
	method string
	path   string
	action cedar.EntityUID
}

var routeMappings = []routeMapping{
	// Gateway routes
	{"POST", "/api/ingest", ActionPublishArtifact},
	{"GET", "/api/evidence", ActionReadEvidence},
	// Gateway admin routes (external boundary)
	{"POST", "/admin/subjects", ActionRequestRegistration},      // Gateway: request subject registration
	{"PUT", "/admin/subjects/", ActionRequestTrustModification}, // Gateway: request trust modification
	// Graph routes
	{"GET", "/api/subjects", ActionQueryEvidence},  // GET /api/subjects (list)
	{"GET", "/api/subjects/", ActionQueryEvidence}, // GET /api/subjects/{id}... (detail, threat-model, evidence, coverage)
	// Locker routes — read-only
	{"GET", "/ledgers", ActionReadEvidence},  // GET /ledgers (exact — list)
	{"GET", "/ledgers/", ActionReadEvidence}, // GET /ledgers/... (info, fetch, verify, tiles)
}

// PrincipalFromJWT constructs a Cedar Publisher entity UID from JWT issuer and subject.
// Format: Publisher::"issuer::sub"
func PrincipalFromJWT(issuer, sub string) cedar.EntityUID {
	return cedar.NewEntityUID(cedar.EntityType("Publisher"), cedar.String(issuer+"::"+sub))
}

// SubjectResource constructs a Cedar Subject resource entity UID from a subject ID.
func SubjectResource(subjectID string) cedar.EntityUID {
	return cedar.NewEntityUID(cedar.EntityType("Subject"), cedar.String(subjectID))
}

// ActionForRoute maps an HTTP method and path to a Cedar action.
// Uses prefix matching for paths ending with "/" (parameterized routes).
// Returns the action EntityUID and true if mapped, or zero value and false if unmapped.
func ActionForRoute(method, path string) (cedar.EntityUID, bool) {
	for _, mapping := range routeMappings {
		if mapping.method != method {
			continue
		}
		if strings.HasSuffix(mapping.path, "/") {
			if strings.HasPrefix(path, mapping.path) {
				return mapping.action, true
			}
		} else if mapping.path == path {
			return mapping.action, true
		}
	}
	return cedar.EntityUID{}, false
}
