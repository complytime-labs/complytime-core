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

// gitLabSubPattern matches GitLab CI token sub claim format:
//
//	project_path:{group}/{project}:ref_type:{branch|tag}:ref:{ref_name}
//
// Example: project_path:my-group/my-project:ref_type:branch:ref:main
var gitLabSubPattern = regexp.MustCompile(`^project_path:[^:]+/[^:]+:ref_type:(branch|tag):ref:.+$`)

// GitLabCIIssuer validates tokens from GitLab CI OIDC.
// The issuer URL is operator-configured (self-hosted or https://gitlab.com).
type GitLabCIIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

const GitLabCIIssuerURL = "https://gitlab.com"

// NewGitLabCIIssuer creates an issuer. Pass "" for issuerURL to use the
// public GitLab URL; pass a custom URL for self-hosted GitLab.
func NewGitLabCIIssuer(ctx context.Context, issuerURL string) (*GitLabCIIssuer, error) {
	if issuerURL == "" {
		issuerURL = GitLabCIIssuerURL
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	jwksURL := issuerURL + "/.well-known/jwks.json"

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for GitLab CI: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering GitLab CI JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching GitLab CI JWKS from %s: %w", jwksURL, err)
	}

	return &GitLabCIIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

func (g *GitLabCIIssuer) URL() string { return g.url }

func (g *GitLabCIIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := g.cache.Lookup(ctx, g.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching GitLab CI JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(g.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("GitLab CI token validation failed: %w", err)
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

// ValidateTrustEntry validates that sub follows GitLab CI token sub format:
//
//	project_path:{group}/{project}:ref_type:{branch|tag}:ref:{ref_name}
func (g *GitLabCIIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if !gitLabSubPattern.MatchString(sub) {
		return fmt.Errorf("invalid GitLab CI sub %q: must match project_path:{group}/{project}:ref_type:{branch|tag}:ref:{ref_name}", sub)
	}
	return nil
}
