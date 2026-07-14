package authz

import (
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// Cedar action entity UIDs
var (
	ActionPublishArtifact = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("publish:artifact"))
	ActionRegisterSubject = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("admin:register-subject"))
	ActionModifyTrust     = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("admin:modify-trust"))
	ActionReadEvidence    = cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("read:evidence"))
)

// routeMapping maps HTTP method + path patterns to Cedar actions
type routeMapping struct {
	method string
	path   string
	action cedar.EntityUID
}

var routeMappings = []routeMapping{
	{"POST", "/api/ingest", ActionPublishArtifact},
	{"POST", "/api/admin/subjects", ActionRegisterSubject},
	{"PUT", "/api/admin/trust", ActionModifyTrust},
	{"PATCH", "/api/admin/trust", ActionModifyTrust},
	{"GET", "/api/evidence", ActionReadEvidence},
	{"GET", "/api/ingest/jobs/", ActionReadEvidence},
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
