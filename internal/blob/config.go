// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds S3-compatible object storage settings (MinIO, AWS S3, RustFS, etc.).
type Config struct {
	Endpoint  string
	Bucket    string
	AccessKey string //nolint:gosec // G117: struct field name, not a credential
	SecretKey string
	UseSSL    bool
}

// ConfigFromEnv loads blob storage settings. The second return is false when
// blob storage is disabled (no BLOB_ENDPOINT).
func ConfigFromEnv() (Config, bool) {
	endpoint := strings.TrimSpace(os.Getenv("BLOB_ENDPOINT"))
	if endpoint == "" {
		return Config{}, false
	}
	cfg := Config{
		Endpoint:  endpoint,
		Bucket:    strings.TrimSpace(os.Getenv("BLOB_BUCKET")),
		AccessKey: strings.TrimSpace(os.Getenv("BLOB_ACCESS_KEY")),
		SecretKey: strings.TrimSpace(os.Getenv("BLOB_SECRET_KEY")),
	}
	if cfg.Bucket == "" {
		cfg.Bucket = "complytime-evidence"
	}
	if v := strings.TrimSpace(os.Getenv("BLOB_USE_SSL")); v != "" {
		cfg.UseSSL, _ = strconv.ParseBool(v)
	}
	cfg.Endpoint, cfg.UseSSL = normalizeEndpoint(cfg.Endpoint, cfg.UseSSL)
	return cfg, true
}

// normalizeEndpoint strips schemes and returns host:port for minio-go.
func normalizeEndpoint(endpoint string, useSSL bool) (string, bool) {
	if !strings.Contains(endpoint, "://") {
		return endpoint, useSSL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint, useSSL
	}
	ssl := useSSL
	switch u.Scheme {
	case "https":
		ssl = true
	case "http":
		ssl = false
	}
	return u.Host, ssl
}
