package publisher

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// spiffeSubPattern matches SPIFFE IDs: spiffe://{trust_domain}/{path}
var spiffeSubPattern = regexp.MustCompile(`^spiffe://[^/]+/.+$`)

// SPIFFEIssuer validates tokens from a SPIFFE OIDC Federation endpoint.
type SPIFFEIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

// NewSPIFFEIssuer creates an issuer for SPIFFE workload identity.
// issuerURL is required — SPIFFE trust domains are always operator-configured.
func NewSPIFFEIssuer(ctx context.Context, issuerURL string) (*SPIFFEIssuer, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuerURL is required for SPIFFE (no default trust domain)")
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	jwksURL := issuerURL + "/.well-known/jwks.json"

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for SPIFFE: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering SPIFFE JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching SPIFFE JWKS from %s: %w", jwksURL, err)
	}

	return &SPIFFEIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

func (s *SPIFFEIssuer) URL() string { return s.url }

func (s *SPIFFEIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := s.cache.Lookup(ctx, s.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching SPIFFE JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(s.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE token validation failed: %w", err)
	}
	if iss, ok := tok.Issuer(); !ok || iss != s.url {
		return nil, fmt.Errorf("issuer mismatch: got %q expected %q", iss, s.url)
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	return &Principal{Issuer: s.url, Sub: sub}, nil
}

// ValidateTrustEntry validates that sub is a valid SPIFFE ID
// (spiffe://{trust_domain}/{path}).
func (s *SPIFFEIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if !spiffeSubPattern.MatchString(sub) {
		return fmt.Errorf("invalid SPIFFE ID %q: must match spiffe://{trust_domain}/{path}", sub)
	}
	return nil
}
