package authz

import (
	"context"
	"embed"
	"log/slog"
	"net/http"

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

// SetAdminContext adds admin flag to the context.
// The JWT middleware can call this if the JWT claims include an admin flag.
func SetAdminContext(ctx context.Context, isAdmin bool) context.Context {
	return context.WithValue(ctx, contextKey("admin"), isAdmin)
}

const serviceKey contextKey = "service"

func SetServiceContext(ctx context.Context, isService bool) context.Context {
	return context.WithValue(ctx, serviceKey, isService)
}

func GetService(ctx context.Context) bool {
	if v, ok := ctx.Value(serviceKey).(bool); ok {
		return v
	}
	return false
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

// LoadEmbeddedPolicies reads the embedded Cedar policy files and returns a PolicySet.
func LoadEmbeddedPolicies() (*cedar.PolicySet, error) {
	data, err := policiesFS.ReadFile("policies/base.cedar")
	if err != nil {
		return nil, err
	}

	ps, err := cedar.NewPolicySetFromBytes("base.cedar", data)
	if err != nil {
		return nil, err
	}

	return ps, nil
}

// Middleware returns an HTTP middleware that performs Cedar authorization.
// It extracts the principal from context, maps the route to an action,
// looks up trust status, builds Cedar entities, and calls IsAuthorized.
//
// If authorization fails (deny or error), it returns 403 Forbidden.
// If the route is not mapped to an action, it returns 403 Forbidden.
func Middleware(ps *cedar.PolicySet, trustLookup TrustLookupFunc) func(http.Handler) http.Handler {
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
				// Locker manage: ledger create doesn't have a subject ID yet.
				// The resource will be a placeholder and Cedar checks admin flag or permits reads.
				if action == ActionRegisterSubject || action == ActionModifyTrust ||
					action == ActionReadEvidence || action == ActionManageLedger {
					subjectID = "*"
				} else {
					http.Error(w, "Forbidden: missing subject ID", http.StatusForbidden)
					return
				}
			}

			// Look up trust status (skip for actions where subject may not exist or isn't relevant)
			trusted := false
			if action != ActionRegisterSubject && action != ActionModifyTrust &&
				action != ActionReadEvidence && action != ActionSealEvidence &&
				action != ActionVerifyEvidence && action != ActionManageLedger {
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

			// For admin actions, check if publisher has admin flag
			// In production, this would come from JWT claims or an admin registry
			// For now, we check the context for an admin flag set by the JWT middleware
			isAdmin := false
			if adminVal := ctx.Value(contextKey("admin")); adminVal != nil {
				if adminBool, ok := adminVal.(bool); ok {
					isAdmin = adminBool
				}
			}

			isService := GetService(ctx)

			entities := cedar.EntityMap{
				principal: cedar.Entity{
					UID: principal,
					Attributes: cedar.NewRecord(cedar.RecordMap{
						"admin":   cedar.Boolean(isAdmin),
						"service": cedar.Boolean(isService),
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
				Context:   cedar.NewRecord(cedar.RecordMap{}),
			}

			// Authorize
			decision, diagnostic := cedar.Authorize(ps, entities, req)
			if decision != cedar.Allow {
				slog.Debug("Cedar authorization denied",
					"principal", principal.String(),
					"action", action.String(),
					"resource", resource.String(),
					"decision", decision.String(),
					"reasons", diagnostic.Reasons,
					"errors", diagnostic.Errors)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Authorization passed
			next.ServeHTTP(w, r)
		})
	}
}
