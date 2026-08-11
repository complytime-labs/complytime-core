package config_test

import (
	"context"
	"flag"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/config"
)

func TestUnmarshalIssuers_PrimaryRequired(t *testing.T) {
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	_, err := config.UnmarshalIssuers(k)
	if err == nil {
		t.Fatal("expected error when OIDC_ISSUER missing")
	}
}

func TestUnmarshalIssuers_WithPrimary(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	cfg, err := config.UnmarshalIssuers(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.URL != "https://idp.example.com" {
		t.Fatalf("unexpected URL: %q", cfg.OIDC.URL)
	}
}

func TestUnmarshalIssuers_KnownShortnames(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("ISSUERS_ENABLED", "github_actions,gcp")
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	cfg, err := config.UnmarshalIssuers(k)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.EnabledShortnames) != 2 {
		t.Fatalf("expected 2 shortnames, got %d", len(cfg.EnabledShortnames))
	}
}

func TestUnmarshalIssuers_UnknownShortnameIsError(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("ISSUERS_ENABLED", "github_actions,bogus_issuer")
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	_, err := config.UnmarshalIssuers(k)
	if err == nil {
		t.Fatal("expected error for unknown shortname")
	}
}

func TestUnmarshalIssuers_CustomRequiresURL(t *testing.T) {
	cfg := config.IssuersConfig{
		OIDC: config.OIDCConfig{URL: "https://idp.example.com"},
		Custom: []config.CustomIssuerConfig{
			{URL: "", Type: "kubernetes"},
		},
	}
	_, _, err := config.BuildIssuers(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for custom issuer with empty URL")
	}
}

func TestUnmarshalIssuers_CustomUnknownTypeIsError(t *testing.T) {
	cfg := config.IssuersConfig{
		OIDC: config.OIDCConfig{URL: "https://idp.example.com"},
		Custom: []config.CustomIssuerConfig{
			{URL: "https://custom.example.com", Type: "unknown_type"},
		},
	}
	_, _, err := config.BuildIssuers(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown custom issuer type")
	}
}

func TestUnmarshalIssuers_GroupClaim(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_GROUP_CLAIM", "realm_access.roles")
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	cfg, err := config.UnmarshalIssuers(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.GroupClaim != "realm_access.roles" {
		t.Fatalf("expected GroupClaim=realm_access.roles, got %q", cfg.OIDC.GroupClaim)
	}
}

func TestUnmarshalIssuers_GroupClaimOptional(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	k, _ := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	cfg, err := config.UnmarshalIssuers(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.GroupClaim != "" {
		t.Fatalf("expected empty GroupClaim when unset, got %q", cfg.OIDC.GroupClaim)
	}
}
