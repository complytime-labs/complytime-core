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

const GitHubActionsIssuerURL = "https://token.actions.githubusercontent.com"

// gitHubSubPattern matches GitHub Actions token sub claim formats:
//
//	repo:{owner}/{name}:{filter_type}:{filter_value}
//
// Examples: repo:org/repo:ref:refs/heads/main, repo:org/repo:environment:production
var gitHubSubPattern = regexp.MustCompile(`^repo:[^/]+/[^/]+:(ref|environment|pull_request|tag|branch):.*$`)

// GitHubActionsIssuer validates tokens from GitHub Actions OIDC.
// Supports github.com and GitHub Enterprise (custom URL).
type GitHubActionsIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

// NewGitHubActionsIssuer creates an issuer. Pass "" for issuerURL to use the
// public GitHub Actions URL; pass a custom URL for GitHub Enterprise.
func NewGitHubActionsIssuer(ctx context.Context, issuerURL string) (*GitHubActionsIssuer, error) {
	if issuerURL == "" {
		issuerURL = GitHubActionsIssuerURL
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	jwksURL := issuerURL + "/.well-known/jwks.json"

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for GitHub Actions: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering GitHub Actions JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching GitHub Actions JWKS from %s: %w", jwksURL, err)
	}

	return &GitHubActionsIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

func (g *GitHubActionsIssuer) URL() string { return g.url }

func (g *GitHubActionsIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := g.cache.Lookup(ctx, g.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching GitHub Actions JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(g.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("GitHub Actions token validation failed: %w", err)
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

// ValidateTrustEntry validates that sub follows GitHub Actions token sub format:
//
//	repo:{owner}/{name}:{filter_type}:{filter_value}
func (g *GitHubActionsIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if !gitHubSubPattern.MatchString(sub) {
		return fmt.Errorf("invalid GitHub Actions sub %q: must match repo:{owner}/{name}:{filter_type}:{value} (e.g. repo:org/repo:ref:refs/heads/main)", sub)
	}
	return nil
}
