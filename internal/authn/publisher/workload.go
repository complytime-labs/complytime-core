package publisher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// WorkloadIssuer validates tokens from a generic OIDC-compatible workload
// identity endpoint. Intended for custom internal CI systems and dev/test
// token servers that don't fit the standard provider types (GitHub Actions,
// GitLab CI, etc.). Sub format is not constrained — any non-empty sub is
// accepted in trust entries. JWKS is fetched from <issuerURL>/.well-known/jwks.json.
type WorkloadIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

// NewWorkloadIssuer creates a publisher issuer for a generic OIDC-compatible
// workload identity endpoint. The issuerURL must serve a JWKS at
// <issuerURL>/.well-known/jwks.json.
func NewWorkloadIssuer(ctx context.Context, issuerURL string) (*WorkloadIssuer, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuerURL is required for workload issuer")
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	jwksURL := issuerURL + "/.well-known/jwks.json"

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for workload issuer: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering workload JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching workload JWKS from %s: %w", jwksURL, err)
	}

	return &WorkloadIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

func (w *WorkloadIssuer) URL() string { return w.url }

func (w *WorkloadIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := w.cache.Lookup(ctx, w.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching workload JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(w.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("workload token validation failed: %w", err)
	}
	if iss, ok := tok.Issuer(); !ok || iss != w.url {
		return nil, fmt.Errorf("issuer mismatch: got %q expected %q", iss, w.url)
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	return &Principal{Issuer: w.url, Sub: sub}, nil
}

// ValidateTrustEntry accepts any non-empty sub — workload issuers are not
// constrained to a specific identity format.
func (w *WorkloadIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	return nil
}
