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

type Principal struct {
	Issuer  string
	Sub     string
	Admin   bool
	Service bool
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
			ctx = authz.SetAdminContext(ctx, p.Admin)
			// TODO: authz.SetServiceContext will be added in Task 4

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
