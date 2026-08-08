package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/knadh/koanf/v2"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
)

// OIDCConfig holds settings for the human IdP.
type OIDCConfig struct {
	URL            string          // OIDC_ISSUER
	ExpectedIssuer string          // OIDC_EXPECTED_ISSUER (optional)
	GroupClaim     string          // OIDC_GROUP_CLAIM (optional — dot-path to group claim)
	AdminGroup     string          // OIDC_ADMIN_GROUP (optional — defaults to complytime-admin)
	AuditorGroup   string          // OIDC_AUDITOR_GROUP (optional — defaults to complytime-auditor)
	GroupMode      authn.GroupMode // OIDC_GROUP_MODE (optional — "audit" logs dropped groups)
}

// CustomIssuerConfig configures an operator-supplied OIDC issuer.
// Type determines which ValidateTrustEntry logic applies.
// Valid types: github, gitlab, gcp, kubernetes, spiffe.
type CustomIssuerConfig struct {
	URL  string `koanf:"url"`
	Type string `koanf:"type"`
}

// IssuersConfig holds all issuer configuration for a service.
type IssuersConfig struct {
	OIDC              OIDCConfig
	EnabledShortnames []string
	Custom            []CustomIssuerConfig
}

// knownShortnames is the registry of built-in public issuers.
// Shortname → constructor called with empty URL (uses hardcoded default).
var knownShortnames = map[string]struct{}{
	"github_actions": {},
	"gitlab":         {},
	"gcp":            {},
}

// UnmarshalIssuers reads issuer config from a loaded koanf instance.
func UnmarshalIssuers(k *koanf.Koanf) (IssuersConfig, error) {
	oidcURL := k.String("oidc.issuer")
	if oidcURL == "" {
		return IssuersConfig{}, fmt.Errorf("oidc.issuer (OIDC_ISSUER) is required")
	}

	cfg := IssuersConfig{
		OIDC: OIDCConfig{
			URL:            oidcURL,
			ExpectedIssuer: k.String("oidc.expected.issuer"),
			GroupClaim:     k.String("oidc.group.claim"),
			AdminGroup:     k.String("oidc.admin.group"),
			AuditorGroup:   k.String("oidc.auditor.group"),
			GroupMode:      authn.GroupMode(k.String("oidc.group.mode")),
		},
	}

	if raw := k.String("issuers.enabled"); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, ok := knownShortnames[name]; !ok {
				return IssuersConfig{}, fmt.Errorf("unknown issuer shortname %q; known: github_actions, gitlab, gcp", name)
			}
			cfg.EnabledShortnames = append(cfg.EnabledShortnames, name)
		}
	}

	if err := k.Unmarshal("issuers.custom", &cfg.Custom); err != nil {
		return IssuersConfig{}, fmt.Errorf("parsing issuers.custom: %w", err)
	}

	return cfg, nil
}

// BuildIssuers constructs the OIDC issuer and all configured publisher issuers.
// Connects to live OIDC endpoints — not suitable for unit tests.
func BuildIssuers(ctx context.Context, cfg IssuersConfig) (*authn.OIDCIssuer, []publisher.PublisherIssuer, error) {
	// Validate all issuer URLs before making any network connections.
	if err := authn.ValidateIssuerURL(cfg.OIDC.URL); err != nil {
		return nil, nil, fmt.Errorf("OIDC issuer: %w", err)
	}
	for _, c := range cfg.Custom {
		if c.URL == "" {
			return nil, nil, fmt.Errorf("custom issuer entry missing url")
		}
		if err := authn.ValidateIssuerURL(c.URL); err != nil {
			return nil, nil, fmt.Errorf("custom issuer: %w", err)
		}
		if err := validateCustomIssuerType(c.Type); err != nil {
			return nil, nil, err
		}
	}

	primary, err := authn.NewOIDCIssuer(ctx, authn.OIDCIssuerConfig{
		URL:            cfg.OIDC.URL,
		ExpectedIssuer: cfg.OIDC.ExpectedIssuer,
		GroupClaim:     cfg.OIDC.GroupClaim,
		AdminGroup:     cfg.OIDC.AdminGroup,
		AuditorGroup:   cfg.OIDC.AuditorGroup,
		GroupMode:      cfg.OIDC.GroupMode,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC issuer: %w", err)
	}

	var publishers []publisher.PublisherIssuer

	for _, name := range cfg.EnabledShortnames {
		issuer, err := buildKnownIssuer(ctx, name)
		if err != nil {
			return nil, nil, fmt.Errorf("known issuer %q: %w", name, err)
		}
		publishers = append(publishers, issuer)
	}

	for _, c := range cfg.Custom {
		issuer, err := buildCustomIssuer(ctx, c)
		if err != nil {
			return nil, nil, fmt.Errorf("custom issuer %q: %w", c.URL, err)
		}
		publishers = append(publishers, issuer)
	}

	return primary, publishers, nil
}

// validateCustomIssuerType returns an error for unrecognised type strings.
func validateCustomIssuerType(t string) error {
	switch t {
	case "github", "gitlab", "gcp", "kubernetes", "spiffe":
		return nil
	default:
		return fmt.Errorf("unknown type %q; valid types: github, gitlab, gcp, kubernetes, spiffe", t)
	}
}

func buildKnownIssuer(ctx context.Context, shortname string) (publisher.PublisherIssuer, error) {
	switch shortname {
	case "github_actions":
		return publisher.NewGitHubActionsIssuer(ctx, "")
	case "gitlab":
		return publisher.NewGitLabCIIssuer(ctx, "")
	case "gcp":
		return publisher.NewGCPWorkloadIssuer(ctx, "")
	default:
		return nil, fmt.Errorf("unknown shortname %q", shortname)
	}
}

func buildCustomIssuer(ctx context.Context, c CustomIssuerConfig) (publisher.PublisherIssuer, error) {
	switch c.Type {
	case "github":
		return publisher.NewGitHubActionsIssuer(ctx, c.URL)
	case "gitlab":
		return publisher.NewGitLabCIIssuer(ctx, c.URL)
	case "gcp":
		return publisher.NewGCPWorkloadIssuer(ctx, c.URL)
	case "kubernetes":
		return publisher.NewKubernetesIssuer(ctx, c.URL)
	case "spiffe":
		return publisher.NewSPIFFEIssuer(ctx, c.URL)
	default:
		return nil, fmt.Errorf("unknown type %q; valid types: github, gitlab, gcp, kubernetes, spiffe", c.Type)
	}
}
