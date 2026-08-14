package locker_test

import (
	"flag"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/locker"
)

func TestLoadLockerConfig_Defaults(t *testing.T) {
	t.Setenv("JWT_AUDIENCE", "complytime-locker")
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := locker.LoadLockerConfig(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NatsURL != "nats://localhost:4222" {
		t.Errorf("unexpected NatsURL: %q", cfg.NatsURL)
	}
	if cfg.ListenAddr != ":8081" {
		t.Errorf("unexpected ListenAddr: %q", cfg.ListenAddr)
	}
	if cfg.DataPath != "/data/ledgers" {
		t.Errorf("unexpected DataPath: %q", cfg.DataPath)
	}
}

func TestLoadLockerConfig_MissingAudience(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	_, err = locker.LoadLockerConfig(k)
	if err == nil {
		t.Fatal("expected error for missing JWT_AUDIENCE")
	}
}
