package publisher

import (
	"context"
	"encoding/json"
	"time"
)

// Principal holds the authenticated identity for a trusted publisher token.
// No role fields — the application layer (registry.go) assigns Publisher: true
// based on issuer class, not on claims within the token.
//
// Mirrors Fulcio's identity.Principal (github.com/sigstore/fulcio/pkg/identity):
// Name() is pp.Sub here; Embed() is not used (we do not issue certificates).
type Principal struct {
	Issuer string
	Sub    string
}

// PublisherIssuer handles authentication for trusted publishing issuers.
//
// Mirrors Fulcio's identity.Issuer interface: Match (here: URL() equality in
// registry.go) selects the issuer; Authenticate validates the raw JWT and
// returns a Principal. We do not import fulcio/pkg/identity because its
// Authenticate path requires a config.FulcioConfig OIDC context backed by
// coreos/go-oidc; our lestrrat-go/jwx JWKS cache is equivalent.
type PublisherIssuer interface {
	URL() string
	Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error)
	ValidateTrustEntry(sub string) error
}

// StoredJWK holds a retrieved static JWK and its expiry.
type StoredJWK struct {
	JWK      json.RawMessage
	NotAfter time.Time
}

// JWKLookup is satisfied by the trust store for runtime-registered scanner JWKs.
type JWKLookup interface {
	LookupJWK(ctx context.Context, issuerID string) (*StoredJWK, error)
}

// JWKLookupFunc adapts a closure to the JWKLookup interface.
type JWKLookupFunc func(ctx context.Context, issuerID string) (*StoredJWK, error)

func (f JWKLookupFunc) LookupJWK(ctx context.Context, issuerID string) (*StoredJWK, error) {
	return f(ctx, issuerID)
}

// JTIStore is satisfied by the trust store for JTI replay prevention.
type JTIStore interface {
	ClaimJTI(ctx context.Context, jti string, ttl time.Duration) error
}
