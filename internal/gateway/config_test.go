package gateway_test

import (
	"flag"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/gateway"
)

func TestLoadGatewayConfig_Defaults(t *testing.T) {
	t.Setenv("JWT_AUDIENCE", "complytime-gateway")
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gateway.LoadGatewayConfig(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NatsURL != "nats://localhost:4222" {
		t.Errorf("unexpected NatsURL: %q", cfg.NatsURL)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("unexpected ListenAddr: %q", cfg.ListenAddr)
	}
}

func TestLoadGatewayConfig_MissingAudience(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.LoadGatewayConfig(k)
	if err == nil {
		t.Fatal("expected error for missing JWT_AUDIENCE")
	}
}

func TestLoadGatewayConfig_EnvOverride(t *testing.T) {
	t.Setenv("JWT_AUDIENCE", "complytime-gateway")
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	t.Setenv("GATEWAY_LISTEN_ADDR", ":9090")
	t.Setenv("NATS_URL", "nats://custom:4222")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gateway.LoadGatewayConfig(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("unexpected ListenAddr: %q", cfg.ListenAddr)
	}
	if cfg.NatsURL != "nats://custom:4222" {
		t.Errorf("unexpected NatsURL: %q", cfg.NatsURL)
	}
}
