package authn

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
)

// IssuerRegistry dispatches JWT authentication and trust-entry validation
// across all configured issuers.
type IssuerRegistry struct {
	oidc       Issuer                               // OIDC_ISSUER — sets Publisher from claims, Scopes from scope claim
	publishers map[string]publisher.PublisherIssuer // URL → trusted publisher Issuer
	jwkStore   publisher.JWKLookup                 // runtime-registered static JWKs
	jtiStore   publisher.JTIStore
	audience   string
}

// NewIssuerRegistry builds a registry. oidc must be non-nil.
func NewIssuerRegistry(oidc Issuer, publishers []publisher.PublisherIssuer, jwkStore publisher.JWKLookup, jtiStore publisher.JTIStore, audience string) *IssuerRegistry {
	m := make(map[string]publisher.PublisherIssuer, len(publishers))
	for _, p := range publishers {
		m[p.URL()] = p
	}
	return &IssuerRegistry{
		oidc:       oidc,
		publishers: m,
		jwkStore:   jwkStore,
		jtiStore:   jtiStore,
		audience:   audience,
	}
}

// Authenticate finds the issuer for the token's iss claim and delegates.
// Order: OIDC issuer → known publishers → runtime-registered static JWKs → reject.
func (r *IssuerRegistry) Authenticate(req *http.Request) (*Principal, error) {
	tokenString, err := extractBearerToken(req)
	if err != nil {
		return nil, err
	}

	iss, err := peekIssuer(tokenString)
	if err != nil {
		return nil, fmt.Errorf("cannot read issuer claim: %w", err)
	}

	if iss == r.oidc.URL() {
		return r.oidc.Authenticate(req.Context(), tokenString, r.audience)
	}

	if pub, ok := r.publishers[iss]; ok {
		pp, err := pub.Authenticate(req.Context(), tokenString, r.audience)
		if err != nil {
			return nil, err
		}
		return &Principal{Issuer: pp.Issuer, Sub: pp.Sub, Publisher: true}, nil
	}

	if r.jwkStore != nil {
		stored, err := r.jwkStore.LookupJWK(req.Context(), iss)
		if err != nil {
			return nil, fmt.Errorf("JWK lookup for %s: %w", iss, err)
		}
		if stored != nil {
			sji := publisher.NewStaticJWKIssuer(iss, &stored.JWK, stored.NotAfter, r.jtiStore)
			pp, err := sji.Authenticate(req.Context(), tokenString, r.audience)
			if err != nil {
				return nil, err
			}
			return &Principal{Issuer: pp.Issuer, Sub: pp.Sub, Publisher: true}, nil
		}
	}

	return nil, fmt.Errorf("issuer %q is not a configured trusted publisher", iss)
}

// ValidateTrustEntry validates that {issuerURL, sub} is a well-formed trust
// entry for the configured issuer type. Returns a user-facing error if not.
func (r *IssuerRegistry) ValidateTrustEntry(issuerURL, sub string) error {
	if issuerURL == r.oidc.URL() {
		return r.oidc.ValidateTrustEntry(sub)
	}
	if pub, ok := r.publishers[issuerURL]; ok {
		return pub.ValidateTrustEntry(sub)
	}
	return fmt.Errorf("issuer %q is not configured as a trusted publisher; add it to the service configuration or use scannerJwk for static JWK issuers", issuerURL)
}

// peekIssuer extracts the iss claim from a JWT without validating the signature.
func peekIssuer(tokenString string) (string, error) {
	tok, err := jwt.ParseInsecure([]byte(tokenString))
	if err != nil {
		return "", fmt.Errorf("parsing token: %w", err)
	}
	iss, ok := tok.Issuer()
	if !ok || iss == "" {
		return "", fmt.Errorf("missing iss claim")
	}
	return strings.TrimRight(iss, "/"), nil
}

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(auth, "Bearer ")
	if !found || token == "" {
		return "", fmt.Errorf("missing or invalid Authorization header")
	}
	return token, nil
}
