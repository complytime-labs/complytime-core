package authn

import (
	"context"
	"net/http"

	"github.com/complytime-labs/complytime-core/internal/authz"
)

type contextKey string

const principalKey contextKey = "authn_principal"

type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// Principal is the authenticated identity for any token class.
// Publisher is true only for workload identity tokens (GitHub Actions, GCP, GitLab, static JWK).
// Scopes are OAuth2 scope strings extracted from the JWT scope claim (human IdP tokens only).
// Groups are extracted from the OIDC group claim (human IdP tokens only).
type Principal struct {
	Issuer    string
	Sub       string
	Publisher bool
	Scopes    []string
	Groups    []string
}

func PrincipalFromContext(ctx context.Context) *Principal {
	if v, ok := ctx.Value(principalKey).(*Principal); ok {
		return v
	}
	return nil
}

func AuthMiddleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := auth.Authenticate(r)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), principalKey, p)
			ctx = authz.SetPublisherContext(ctx, p.Issuer, p.Sub)
			ctx = authz.SetPublisherFlagContext(ctx, p.Publisher)
			ctx = authz.SetScopesContext(ctx, p.Scopes)
			ctx = authz.SetGroupsContext(ctx, p.Groups)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
