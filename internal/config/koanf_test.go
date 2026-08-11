package config_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/config"
)

func TestLoad_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("nats:\n  url: nats://from-file:4222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NATS_URL", "nats://from-env:4222")
	k, err := config.Load(cfgFile, flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	if got := k.String("nats.url"); got != "nats://from-env:4222" {
		t.Fatalf("env should win over file, got %q", got)
	}
}

func TestLoad_FileUsedWhenNoEnv(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("nats:\n  url: nats://from-file:4222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("NATS_URL")
	k, err := config.Load(cfgFile, flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatal(err)
	}
	if got := k.String("nats.url"); got != "nats://from-file:4222" {
		t.Fatalf("expected file value, got %q", got)
	}
}

func TestLoad_MissingFileIsError(t *testing.T) {
	_, err := config.Load("/nonexistent/path.yaml", flag.NewFlagSet("test", flag.ContinueOnError))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoad_EmptyPathSkipsFile(t *testing.T) {
	_, err := config.Load("", flag.NewFlagSet("test", flag.ContinueOnError))
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
}
