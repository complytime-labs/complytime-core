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
	knownGroups    map[string]struct{}
	groupMode      GroupMode
}

// OIDCIssuerConfig holds configuration for the human IdP.
type OIDCIssuerConfig struct {
	URL            string    // required — OIDC discovery base URL (used for JWKS fetch)
	ExpectedIssuer string    // optional — overrides iss claim validation when internal URL ≠ token issuer
	GroupClaim     string    // optional — dot-path to group claim (e.g. "groups", "realm_access.roles")
	AdminGroup     string    // optional — group name for admin role; defaults to DefaultAdminGroup
	AuditorGroup   string    // optional — group name for auditor role; defaults to DefaultAuditorGroup
	GroupMode      GroupMode // optional — "audit" logs dropped groups; default "enforce"
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

// GroupMode controls how unrecognized groups are handled.
type GroupMode string

const (
	// GroupModeEnforce silently drops unrecognized groups. Default.
	GroupModeEnforce GroupMode = "enforce"
	// GroupModeAudit drops unrecognized groups but logs them for operator diagnostics.
	GroupModeAudit GroupMode = "audit"
)

// DefaultAdminGroup and DefaultAuditorGroup are the group names used when
// OIDC_ADMIN_GROUP / OIDC_AUDITOR_GROUP are not set. Cedar base policies
// reference these same values; change both together.
const (
	DefaultAdminGroup   = "complytime-admin"
	DefaultAuditorGroup = "complytime-auditor"
)

// ExtractGroups reads groups from the JWT claims using the configured dot-path,
// normalizes to lowercase, and returns the subset present in knownGroups.
// Returns nil if groupClaim is empty or the claim is missing.
// knownGroups is the operator-configured set; build it from OIDCIssuerConfig.
func ExtractGroups(claims map[string]any, groupClaim string, knownGroups map[string]struct{}) []string {
	recognized, _ := extractGroupsWithDropped(claims, groupClaim, knownGroups)
	return recognized
}

// extractGroupsWithDropped returns both recognized and dropped groups in one pass.
func extractGroupsWithDropped(claims map[string]any, groupClaim string, knownGroups map[string]struct{}) (recognized, dropped []string) {
	raw := ExtractClaimByPath(claims, groupClaim)
	for _, g := range raw {
		normalized := strings.ToLower(g)
		if _, known := knownGroups[normalized]; known {
			recognized = append(recognized, normalized)
		} else {
			dropped = append(dropped, normalized)
		}
	}
	return
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

	adminGroup := cfg.AdminGroup
	if adminGroup == "" {
		adminGroup = DefaultAdminGroup
	}
	auditorGroup := cfg.AuditorGroup
	if auditorGroup == "" {
		auditorGroup = DefaultAuditorGroup
	}
	knownGroups := map[string]struct{}{
		adminGroup:   {},
		auditorGroup: {},
	}

	groupMode := cfg.GroupMode
	switch groupMode {
	case GroupModeEnforce, GroupModeAudit:
	case "":
		groupMode = GroupModeEnforce
	default:
		return nil, fmt.Errorf("invalid OIDC_GROUP_MODE %q: must be %q or %q", cfg.GroupMode, GroupModeEnforce, GroupModeAudit)
	}

	if cfg.GroupClaim != "" {
		slog.Info("group-based authorization enabled",
			"claim_path", cfg.GroupClaim,
			"admin_group", adminGroup,
			"auditor_group", auditorGroup,
			"mode", groupMode,
			"issuer", issuerURL)
	}

	return &OIDCIssuer{
		url:            issuerURL,
		expectedIssuer: expectedIssuer,
		jwksURL:        jwksURL,
		cache:          cache,
		groupClaim:     cfg.GroupClaim,
		knownGroups:    knownGroups,
		groupMode:      groupMode,
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

	if o.groupClaim != "" {
		recognized, dropped := extractGroupsWithDropped(claims, o.groupClaim, o.knownGroups)
		principal.Groups = recognized

		if len(recognized) == 0 {
			slog.Warn("group claim configured but no recognized groups extracted",
				"claim_path", o.groupClaim, "sub", sub)
		}
		if o.groupMode == GroupModeAudit && len(dropped) > 0 {
			slog.Warn("audit: groups in token not recognized — verify OIDC_ADMIN_GROUP / OIDC_AUDITOR_GROUP match your IdP",
				"dropped", dropped, "recognized", recognized,
				"claim_path", o.groupClaim, "sub", sub)
		}
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

