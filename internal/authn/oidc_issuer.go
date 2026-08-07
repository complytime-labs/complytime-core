package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// OIDCIssuer handles the operator's human IdP. Validates JWTs via JWKS
// discovery and extracts OAuth2 scopes from the standard scope claim.
type OIDCIssuer struct {
	url            string
	expectedIssuer string // iss claim value; may differ from url in split-brain deployments
	jwksURL        string
	cache          *jwk.Cache
	groupClaim     string
}

// OIDCIssuerConfig holds configuration for the human IdP.
type OIDCIssuerConfig struct {
	URL            string // required — OIDC discovery base URL (used for JWKS fetch)
	ExpectedIssuer string // optional — overrides iss claim validation when internal URL ≠ token issuer
	GroupClaim     string // optional — dot-path to group claim (e.g. "groups", "realm_access.roles")
}

// knownScopes is the allowlist of scopes the application recognises.
// Scopes not in this set are silently dropped.
var knownScopes = map[string]struct{}{
	"complytime:admin": {},
	"complytime:audit": {},
	"complytime:read":  {},
}

// ExtractScopes reads the standard OAuth2 scope claim (space-separated string)
// and returns the subset that appears in knownScopes.
func ExtractScopes(claims map[string]any) []string {
	scopeVal, ok := claims["scope"].(string)
	if !ok || scopeVal == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Fields(scopeVal) {
		if _, known := knownScopes[s]; known {
			out = append(out, s)
		}
	}
	return out
}

// knownGroups is the allowlist of groups the application recognises.
// Groups not in this set are silently dropped — defense-in-depth against
// directory-sourced claims with a weaker trust model than OAuth2 scopes.
var knownGroups = map[string]struct{}{
	"complytime-admin":   {},
	"complytime-auditor": {},
}

// ExtractGroups reads groups from the JWT claims using the configured dot-path,
// normalizes to lowercase, and returns the subset that appears in knownGroups.
// Returns nil if groupClaim is empty or the claim is missing.
func ExtractGroups(claims map[string]any, groupClaim string) []string {
	raw := ExtractClaimByPath(claims, groupClaim)
	if len(raw) == 0 {
		return nil
	}
	var out []string
	for _, g := range raw {
		normalized := strings.ToLower(g)
		if _, known := knownGroups[normalized]; known {
			out = append(out, normalized)
		}
	}
	return out
}

// fetchJWKSURL fetches the OIDC discovery document and returns the jwks_uri.
func fetchJWKSURL(issuerURL string) (string, error) {
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery document returned status %d", resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decoding discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in discovery document")
	}
	return doc.JWKSURI, nil
}

// NewOIDCIssuer creates an OIDCIssuer and pre-fetches JWKS.
func NewOIDCIssuer(ctx context.Context, cfg OIDCIssuerConfig) (*OIDCIssuer, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("OIDC_ISSUER is required")
	}

	issuerURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	expectedIssuer := issuerURL
	if cfg.ExpectedIssuer != "" {
		expectedIssuer = strings.TrimRight(strings.TrimSpace(cfg.ExpectedIssuer), "/")
	}
	jwksURL, err := fetchJWKSURL(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", issuerURL, err)
	}

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
	}

	if cfg.GroupClaim != "" {
		slog.Info("group-based authorization enabled",
			"claim_path", cfg.GroupClaim,
			"issuer", issuerURL)
	}

	return &OIDCIssuer{
		url:            issuerURL,
		expectedIssuer: expectedIssuer,
		jwksURL:        jwksURL,
		cache:          cache,
		groupClaim:     cfg.GroupClaim,
	}, nil
}

// URL returns the expected issuer claim value. Registry compares the token's
// iss claim against this to decide dispatch. When ExpectedIssuer is configured
// (split-brain), this differs from the JWKS fetch URL.
func (o *OIDCIssuer) URL() string { return o.expectedIssuer }

func (o *OIDCIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := o.cache.Lookup(ctx, o.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(o.expectedIssuer),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("OIDC issuer validation failed: %w", err)
	}
	iss, ok := tok.Issuer()
	if !ok || iss != o.expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: got %q expected %q", iss, o.expectedIssuer)
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	principal := &Principal{Issuer: o.expectedIssuer, Sub: sub}

	data, err := json.Marshal(tok)
	if err != nil {
		slog.Warn("failed to marshal OIDC token for scope extraction", "error", err)
		return principal, nil
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		slog.Warn("failed to unmarshal OIDC token for scope extraction", "error", err)
		return principal, nil
	}

	// Human IdP tokens carry OAuth2 scopes for access control.
	// Publisher-class is set by the registry dispatch, never by this issuer.
	principal.Scopes = ExtractScopes(claims)
	principal.Groups = ExtractGroups(claims, o.groupClaim)

	if o.groupClaim != "" && len(principal.Groups) == 0 {
		slog.Warn("group claim configured but no recognized groups extracted",
			"claim_path", o.groupClaim, "sub", sub)
	}

	return principal, nil
}

// ValidateTrustEntry: any sub from the OIDC IdP is valid as a per-subject trusted publisher.
func (o *OIDCIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	return nil
}

