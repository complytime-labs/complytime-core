// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"log/slog"
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
	TesseraPath               string
	TesseraSignerKeyPath      string
	TesseraCheckpointInterval time.Duration
	TesseraWitnessPolicyPath  string
	TesseraWitnessTimeout     time.Duration
	TesseraWitnessFailOpen    bool

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

	// Ingest Rate Limiting
	IngestRateLimit float64
	IngestRateBurst int
}

// GatewayFromEnv loads gateway configuration from environment variables.
// Returns an error listing all missing required variables.
func GatewayFromEnv() (*GatewayConfig, error) {
	cfg := &GatewayConfig{
		PostgresURL:               os.Getenv("POSTGRES_URL"),
		NatsURL:                   os.Getenv("NATS_URL"),
		Port:                      envOr("PORT", "8080"),
		ListenHost:                envOr("LISTEN_HOST", "0.0.0.0"),
		TesseraPath:               envOr("TESSERA_PATH", "/data/tessera"),
		TesseraSignerKeyPath:      os.Getenv("TESSERA_SIGNER_KEY_PATH"),
		TesseraCheckpointInterval: envDuration("TESSERA_CHECKPOINT_INTERVAL", 10*time.Minute),
		TesseraWitnessPolicyPath:  os.Getenv("TESSERA_WITNESS_POLICY_PATH"),
		TesseraWitnessTimeout:     envDuration("TESSERA_WITNESS_TIMEOUT", 5*time.Second),
		TesseraWitnessFailOpen:    os.Getenv("TESSERA_WITNESS_FAIL_OPEN") == "true",
		JWTIssuers:                splitComma(os.Getenv("JWT_ISSUERS")),
		JWTAudience:               os.Getenv("JWT_AUDIENCE"),
		CORSOrigins:               splitComma(os.Getenv("CORS_ORIGINS")),
		OAuth2ProxyEnabled:        os.Getenv("OAUTH2_PROXY_ENABLED") != "false",
		WorkbenchURL:              envOr("WORKBENCH_URL", "http://studio-workbench:8090"),
		BlobEndpoint:              os.Getenv("BLOB_ENDPOINT"),
		BlobBucket:                os.Getenv("BLOB_BUCKET"),
		BlobAccessKey:             os.Getenv("BLOB_ACCESS_KEY"),
		BlobSecretKey:             os.Getenv("BLOB_SECRET_KEY"),
		BlobUseSSL:                os.Getenv("BLOB_USE_SSL") == "true",
		StudioVersion:             envOr("STUDIO_VERSION", "dev"),
		GitHubOrg:                 os.Getenv("GITHUB_ORG"),
		GitHubRepo:                envOr("GITHUB_REPO", "complytime-studio"),
		RegistryInsecure:          os.Getenv("REGISTRY_INSECURE") == "true",
		IngestMaxDeliver:          envInt("NATS_INGEST_MAX_DELIVER", 5),
		IngestAckWait:             envDuration("NATS_INGEST_ACK_WAIT", 30*time.Second),
		KnownRegistries:           splitComma(os.Getenv("KNOWN_REGISTRIES")),
		KnownEngines:              splitComma(os.Getenv("KNOWN_ENGINES")),
		IngestRateLimit:           envFloat("INGEST_RATE_LIMIT", 10),
		IngestRateBurst:           envInt("INGEST_RATE_BURST", 20),
	}

	// Clamp rate-limit values to reasonable upper bounds.
	const maxRate = 10000.0
	const maxBurst = 100000
	if cfg.IngestRateLimit > maxRate {
		slog.Warn("ingest rate limit clamped to max", "configured", cfg.IngestRateLimit, "max", maxRate)
		cfg.IngestRateLimit = maxRate
	}
	if cfg.IngestRateBurst > maxBurst {
		slog.Warn("ingest rate burst clamped to max", "configured", cfg.IngestRateBurst, "max", maxBurst)
		cfg.IngestRateBurst = maxBurst
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

func envFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		slog.Warn("env var parse failed, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return f
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("env var parse failed, using default", "key", key, "value", v, "default", fallback)
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
