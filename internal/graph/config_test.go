package graph_test

import (
	"flag"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/graph"
)

func TestLoadGraphConfig_AllRequired(t *testing.T) {
	t.Setenv("NATS_URL", "nats://nats:4222")
	t.Setenv("LOCKER_URL", "http://locker:8081")
	t.Setenv("TOKEN_FILE", "/var/run/token")
	t.Setenv("MEMGRAPH_URL", "bolt://memgraph:7687")
	t.Setenv("JWT_AUDIENCE", "complytime-graph")
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_CLIENT_ID", "complytime")
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := graph.LoadGraphConfig(k)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8082" {
		t.Errorf("unexpected ListenAddr: %q", cfg.ListenAddr)
	}
}

func TestLoadGraphConfig_MissingRequired(t *testing.T) {
	t.Setenv("NATS_URL", "nats://nats:4222")
	// LOCKER_URL, TOKEN_FILE, MEMGRAPH_URL, JWT_AUDIENCE missing
	k, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	_, err = graph.LoadGraphConfig(k)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
}
