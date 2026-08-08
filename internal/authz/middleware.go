package authz

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

//go:embed policies/*.cedar
var policiesFS embed.FS

// TrustLookupFunc determines if a publisher (identified by issuer + sub) is trusted
// for a given subject. Returns true if trusted, false if not, and an error if lookup fails.
type TrustLookupFunc func(ctx context.Context, subjectID, issuer, sub string) (bool, error)

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const (
	publisherIssuerKey contextKey = "publisher_issuer"
	publisherSubKey    contextKey = "publisher_sub"
	subjectIDKey       contextKey = "subject_id"
)

// SetPublisherContext adds publisher identity (issuer + sub) to the context.
// The JWT middleware (Task 9) will call this after validating the JWT.
func SetPublisherContext(ctx context.Context, issuer, sub string) context.Context {
	ctx = context.WithValue(ctx, publisherIssuerKey, issuer)
	ctx = context.WithValue(ctx, publisherSubKey, sub)
	return ctx
}

const publisherFlagKey contextKey = "publisher_flag"

func SetPublisherFlagContext(ctx context.Context, isPublisher bool) context.Context {
	return context.WithValue(ctx, publisherFlagKey, isPublisher)
}

func GetPublisherFlag(ctx context.Context) bool {
	if v, ok := ctx.Value(publisherFlagKey).(bool); ok {
		return v
	}
	return false
}

const scopesKey contextKey = "scopes"

// SetScopesContext adds OAuth2 scopes to the context.
// The JWT middleware will call this after extracting scopes from the JWT.
func SetScopesContext(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, scopesKey, scopes)
}

func GetScopes(ctx context.Context) []string {
	if v, ok := ctx.Value(scopesKey).([]string); ok {
		return v
	}
	return nil
}

const groupsKey contextKey = "groups"

// SetGroupsContext adds IdP group memberships to the context.
func SetGroupsContext(ctx context.Context, groups []string) context.Context {
	return context.WithValue(ctx, groupsKey, groups)
}

func GetGroups(ctx context.Context) []string {
	if v, ok := ctx.Value(groupsKey).([]string); ok {
		return v
	}
	return nil
}

// GetPublisher retrieves publisher identity from the context.
// Returns empty strings if not set.
func GetPublisher(ctx context.Context) (issuer, sub string) {
	if v, ok := ctx.Value(publisherIssuerKey).(string); ok {
		issuer = v
	}
	if v, ok := ctx.Value(publisherSubKey).(string); ok {
		sub = v
	}
	return issuer, sub
}

// SetSubjectIDContext adds the subject ID to the context.
// HTTP handlers (Task 7) will call this after extracting subject ID from the request.
func SetSubjectIDContext(ctx context.Context, subjectID string) context.Context {
	return context.WithValue(ctx, subjectIDKey, subjectID)
}

// GetSubjectID retrieves the subject ID from the context.
// Returns empty string if not set.
func GetSubjectID(ctx context.Context) string {
	if v, ok := ctx.Value(subjectIDKey).(string); ok {
		return v
	}
	return ""
}

// LoadEmbeddedPolicies reads the embedded Cedar base policy and merges
// any *.cedar files from policyDir (if non-empty) into one PolicySet.
func LoadEmbeddedPolicies(policyDir string) (*cedar.PolicySet, error) {
	data, err := policiesFS.ReadFile("policies/base.cedar")
	if err != nil {
		return nil, fmt.Errorf("reading embedded base.cedar: %w", err)
	}

	ps, err := cedar.NewPolicySetFromBytes("base.cedar", data)
	if err != nil {
		return nil, fmt.Errorf("parsing base.cedar: %w", err)
	}

	if policyDir == "" {
		return ps, nil
	}

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, fmt.Errorf("reading CEDAR_POLICY_DIR %s: %w", policyDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cedar") {
			continue
		}
		path := filepath.Join(policyDir, entry.Name())
		fileData, err := os.ReadFile(path) //nolint:gosec // G304: path validated above
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		extra, err := cedar.NewPolicySetFromBytes(entry.Name(), fileData)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		for id, policy := range maps.Collect(extra.All()) {
			ps.Add(id, policy)
		}
	}

	return ps, nil
}

// MiddlewareConfig carries operator-configured values injected into every
// Cedar authorization context. Group names must match the Cedar base policy
// and the IdP groups configured via OIDC_ADMIN_GROUP / OIDC_AUDITOR_GROUP.
// Empty fields fall back to the Cedar base policy defaults.
type MiddlewareConfig struct {
	AdminGroup   string // default: "complytime-admin"
	AuditorGroup string // default: "complytime-auditor"
}

func (c MiddlewareConfig) adminGroup() string {
	if c.AdminGroup != "" {
		return c.AdminGroup
	}
	return "complytime-admin"
}

func (c MiddlewareConfig) auditorGroup() string {
	if c.AuditorGroup != "" {
		return c.AuditorGroup
	}
	return "complytime-auditor"
}

// Middleware returns an HTTP middleware that performs Cedar authorization.
// It extracts the principal from context, maps the route to an action,
// looks up trust status, builds Cedar entities, and calls IsAuthorized.
//
// If authorization fails (deny or error), it returns 403 Forbidden.
// If the route is not mapped to an action, it returns 403 Forbidden.
func Middleware(ps *cedar.PolicySet, trustLookup TrustLookupFunc, cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract principal from context
			issuer, sub := GetPublisher(ctx)
			if issuer == "" || sub == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Map route to action first (needed to determine if subject ID is required)
			action, ok := ActionForRoute(r.Method, r.URL.Path)
			if !ok {
				http.Error(w, "Forbidden: unmapped route", http.StatusForbidden)
				return
			}

			// Extract subject ID from context
			// For admin actions (register-subject), subject ID may be in the request body
			// In that case, we use a placeholder for authorization and the handler validates it
			subjectID := GetSubjectID(ctx)
			if subjectID == "" {
				// Admin actions and read operations can proceed without a subject ID.
				// Admin: the subject may not exist yet. Read: job status is not subject-scoped.
				// Query: graph service routes carry subject ID in URL path, not context header.
				// The resource will be a placeholder and Cedar checks admin flag or permits reads.
				if action == ActionRequestRegistration || action == ActionRequestTrustModification ||
					action == ActionReadEvidence || action == ActionVerifyEvidence ||
					action == ActionQueryEvidence {
					subjectID = "*"
				} else {
					http.Error(w, "Forbidden: missing subject ID", http.StatusForbidden)
					return
				}
			}

			// Look up trust status (skip for actions where subject may not exist or isn't relevant)
			trusted := false
			if action != ActionRequestRegistration && action != ActionRequestTrustModification &&
				action != ActionReadEvidence && action != ActionVerifyEvidence &&
				action != ActionQueryEvidence {
				if trustLookup != nil {
					var err error
					trusted, err = trustLookup(ctx, subjectID, issuer, sub)
					if err != nil {
						http.Error(w, "Forbidden: trust lookup failed", http.StatusForbidden)
						return
					}
				}
			}

			// Build Cedar entities
			principal := PrincipalFromJWT(issuer, sub)
			resource := SubjectResource(subjectID)

			isPublisher := GetPublisherFlag(ctx)
			rawScopes := GetScopes(ctx)
			cedarScopes := make([]cedar.Value, len(rawScopes))
			for i, s := range rawScopes {
				cedarScopes[i] = cedar.String(s)
			}

			rawGroups := GetGroups(ctx)
			cedarGroups := make([]cedar.Value, len(rawGroups))
			for i, g := range rawGroups {
				cedarGroups[i] = cedar.String(g)
			}

			entities := cedar.EntityMap{
				principal: cedar.Entity{
					UID: principal,
					Attributes: cedar.NewRecord(cedar.RecordMap{
						"publisher": cedar.Boolean(isPublisher),
						"scopes":    cedar.NewSet(cedarScopes...),
						"groups":    cedar.NewSet(cedarGroups...),
						"issuer":    cedar.String(issuer),
						"sub":       cedar.String(sub),
					}),
				},
				resource: cedar.Entity{
					UID:        resource,
					Attributes: cedar.NewRecord(cedar.RecordMap{"publisher_trusted": cedar.Boolean(trusted)}),
				},
			}

			// Build authorization request
			req := cedar.Request{
				Principal: principal,
				Action:    action,
				Resource:  resource,
				Context: cedar.NewRecord(cedar.RecordMap{
					"admin_group":   cedar.String(cfg.adminGroup()),
					"auditor_group": cedar.String(cfg.auditorGroup()),
				}),
			}

			// Authorize
			decision, diagnostic := cedar.Authorize(ps, entities, req)
			if decision != cedar.Allow {
				slog.Warn("Cedar authorization denied",
					"principal", principal.String(),
					"action", action.String(),
					"resource", resource.String(),
					"decision", decision.String(),
					"scopes", rawScopes,
					"groups", rawGroups,
					"reasons", diagnostic.Reasons,
					"errors", diagnostic.Errors)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Authorization passed
			slog.Info("Cedar authorization allowed",
				"principal", principal.String(),
				"action", action.String(),
				"resource", resource.String())
			next.ServeHTTP(w, r)
		})
	}
}
