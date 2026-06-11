// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// GatewayConfig holds all configuration for the gateway binary.
type GatewayConfig struct {
	// Required
	PostgresURL string
	NatsURL     string

	// Server
	Port       string
	ListenHost string

	// Tessera
	TesseraPath string

	// JWT / Publisher Identity
	JWTIssuers  []string
	JWTAudience string

	// CORS
	CORSOrigins []string

	// OAuth2 Proxy
	OAuth2ProxyEnabled bool

	// Workbench
	WorkbenchURL string

	// Blob Storage (optional)
	BlobEndpoint  string
	BlobBucket    string
	BlobAccessKey string
	BlobSecretKey string
	BlobUseSSL    bool

	// Platform Info
	StudioVersion string
	GitHubOrg     string
	GitHubRepo    string

	// Registry
	RegistryInsecure bool

	// JetStream Tuning
	IngestMaxDeliver int
	IngestAckWait    time.Duration

	// Certifier
	KnownRegistries []string
	KnownEngines    []string
}

// GatewayFromEnv loads gateway configuration from environment variables.
// Returns an error listing all missing required variables.
func GatewayFromEnv() (*GatewayConfig, error) {
	cfg := &GatewayConfig{
		PostgresURL:        os.Getenv("POSTGRES_URL"),
		NatsURL:            os.Getenv("NATS_URL"),
		Port:               envOr("PORT", "8080"),
		ListenHost:         envOr("LISTEN_HOST", "0.0.0.0"),
		TesseraPath:        envOr("TESSERA_PATH", "/data/tessera"),
		JWTIssuers:         splitComma(os.Getenv("JWT_ISSUERS")),
		JWTAudience:        os.Getenv("JWT_AUDIENCE"),
		CORSOrigins:        splitComma(os.Getenv("CORS_ORIGINS")),
		OAuth2ProxyEnabled: os.Getenv("OAUTH2_PROXY_ENABLED") != "false",
		WorkbenchURL:       envOr("WORKBENCH_URL", "http://studio-workbench:8090"),
		BlobEndpoint:       os.Getenv("BLOB_ENDPOINT"),
		BlobBucket:         os.Getenv("BLOB_BUCKET"),
		BlobAccessKey:      os.Getenv("BLOB_ACCESS_KEY"),
		BlobSecretKey:      os.Getenv("BLOB_SECRET_KEY"),
		BlobUseSSL:         os.Getenv("BLOB_USE_SSL") == "true",
		StudioVersion:      envOr("STUDIO_VERSION", "dev"),
		GitHubOrg:          os.Getenv("GITHUB_ORG"),
		GitHubRepo:         envOr("GITHUB_REPO", "complytime-studio"),
		RegistryInsecure:   os.Getenv("REGISTRY_INSECURE") == "true",
		IngestMaxDeliver:   envInt("NATS_INGEST_MAX_DELIVER", 5),
		IngestAckWait:      envDuration("NATS_INGEST_ACK_WAIT", 30*time.Second),
		KnownRegistries:    splitComma(os.Getenv("KNOWN_REGISTRIES")),
		KnownEngines:       splitComma(os.Getenv("KNOWN_ENGINES")),
	}

	var missing []string
	if cfg.PostgresURL == "" {
		missing = append(missing, "POSTGRES_URL")
	}
	if cfg.NatsURL == "" {
		missing = append(missing, "NATS_URL")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// WitnessConfig holds all configuration for the witness binary.
type WitnessConfig struct {
	PostgresURL string
	ConfigPath  string
	StatePath   string
	TesseraPath string
}

// WitnessFromEnv loads witness configuration from environment variables.
func WitnessFromEnv() (*WitnessConfig, error) {
	cfg := &WitnessConfig{
		PostgresURL: os.Getenv("POSTGRES_URL"),
		ConfigPath:  envOr("WITNESS_CONFIG_PATH", "/etc/witness/config.yaml"),
		StatePath:   envOr("WITNESS_STATE_PATH", "/var/lib/witness/state.json"),
		TesseraPath: envOr("TESSERA_PATH", "/var/lib/tessera"),
	}

	if cfg.PostgresURL == "" {
		return nil, fmt.Errorf("missing required environment variable: POSTGRES_URL")
	}

	return cfg, nil
}

// BlobEnabled returns true if blob storage is configured.
func (c *GatewayConfig) BlobEnabled() bool {
	return strings.TrimSpace(c.BlobEndpoint) != ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
