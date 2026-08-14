package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// DiscoverJWKSURI fetches the OIDC discovery document for issuerURL and returns
// the jwks_uri. Used by OIDCIssuer and KubernetesIssuer at startup.
func DiscoverJWKSURI(ctx context.Context, issuerURL string) (string, error) {
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("building discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint %s returned %d", discoveryURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading discovery response: %w", err)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parsing discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document at %s missing jwks_uri", discoveryURL)
	}
	return doc.JWKSURI, nil
}
