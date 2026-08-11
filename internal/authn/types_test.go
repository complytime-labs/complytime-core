package authn_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/authn"
	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
)

// Compile-time shape checks for exported types.

func TestPrincipalShape(t *testing.T) {
	p := authn.Principal{
		Issuer:    "https://issuer.example.com",
		Sub:       "alice",
		Publisher: false,
		Scopes:    []string{"complytime:audit"},
	}
	if p.Publisher {
		t.Fatal("Publisher must default false for human IdP tokens")
	}
	if len(p.Scopes) == 0 {
		t.Fatal("Scopes field must be accessible")
	}
}

func TestPrincipalGroupsShape(t *testing.T) {
	p := authn.Principal{
		Issuer: "https://issuer.example.com",
		Sub:    "alice",
		Groups: []string{"complytime-admin"},
	}
	if len(p.Groups) != 1 || p.Groups[0] != "complytime-admin" {
		t.Fatal("Groups field must be accessible")
	}
}

func TestPublisherPrincipalShape(t *testing.T) {
	p := publisher.Principal{
		Issuer: "https://token.actions.githubusercontent.com",
		Sub:    "repo:org/repo:ref:refs/heads/main",
	}
	if p.Issuer == "" {
		t.Fatal("Issuer must be accessible")
	}
}

func TestJWKLookupFuncSatisfiesInterface(t *testing.T) {
	var _ publisher.JWKLookup = publisher.JWKLookupFunc(nil)
}
