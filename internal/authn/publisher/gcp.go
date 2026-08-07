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

const (
	GCPWorkloadIssuerURL = "https://accounts.google.com"
	gcpDefaultJWKSURL    = "https://www.googleapis.com/oauth2/v3/certs"
)

// gcpSubPattern matches GCP Workload Identity pool format or service account email.
// Accepts:
//   - https://iam.googleapis.com/... (workload identity pool)
//   - {name}@{project}.iam.gserviceaccount.com (service account)
var gcpSubPattern = regexp.MustCompile(`^(https://iam\.googleapis\.com/|[^@]+@[^@]+\.iam\.gserviceaccount\.com$)`)

// GCPWorkloadIssuer validates tokens from GCP Workload Identity Federation.
type GCPWorkloadIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

// NewGCPWorkloadIssuer creates an issuer. Pass "" for issuerURL to use the
// standard GCP issuer URL (https://accounts.google.com).
func NewGCPWorkloadIssuer(ctx context.Context, issuerURL string) (*GCPWorkloadIssuer, error) {
	if issuerURL == "" {
		issuerURL = GCPWorkloadIssuerURL
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	jwksURL := gcpDefaultJWKSURL
	if issuerURL != GCPWorkloadIssuerURL {
		jwksURL = issuerURL + "/.well-known/jwks.json"
	}

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for GCP Workload Identity: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering GCP Workload Identity JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching GCP Workload Identity JWKS from %s: %w", jwksURL, err)
	}

	return &GCPWorkloadIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

func (g *GCPWorkloadIssuer) URL() string { return g.url }

func (g *GCPWorkloadIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := g.cache.Lookup(ctx, g.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching GCP Workload Identity JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(g.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("GCP Workload Identity token validation failed: %w", err)
	}
	if iss, ok := tok.Issuer(); !ok || iss != g.url {
		return nil, fmt.Errorf("issuer mismatch: got %q expected %q", iss, g.url)
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	return &Principal{Issuer: g.url, Sub: sub}, nil
}

// ValidateTrustEntry validates that sub is a GCP Workload Identity pool member
// or a service account email.
func (g *GCPWorkloadIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if !gcpSubPattern.MatchString(sub) {
		return fmt.Errorf("invalid GCP Workload Identity sub %q: must be a workload identity pool URL (https://iam.googleapis.com/...) or service account email ({name}@{project}.iam.gserviceaccount.com)", sub)
	}
	return nil
}
