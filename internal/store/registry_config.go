// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var registryHTTPClient = &http.Client{Timeout: 30 * time.Second}

// RegistryConfig holds operator-configured registry authentication.
// Two tiers: insecure (PlainHTTP, no auth) and configured read-only credentials.
type RegistryConfig struct {
	InsecureHosts []string
	Credentials   map[string]string
}

func (rc *RegistryConfig) IsInsecure(host string) bool {
	if rc == nil {
		return false
	}
	for _, h := range rc.InsecureHosts {
		if h == host {
			return true
		}
	}
	return false
}

func (rc *RegistryConfig) TokenForHost(host string) (string, bool) {
	if rc == nil || rc.Credentials == nil {
		return "", false
	}
	t, ok := rc.Credentials[host]
	return t, ok
}

// Repository builds an oras remote.Repository for the given OCI reference
// with appropriate auth and transport settings.
func (rc *RegistryConfig) Repository(ref string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	host := repo.Reference.Host()

	if rc.IsInsecure(host) {
		repo.PlainHTTP = true
		return repo, nil
	}

	token, ok := rc.TokenForHost(host)
	if !ok {
		return nil, fmt.Errorf("no registry credentials configured for %q — contact your administrator", host)
	}

	repo.Client = &auth.Client{
		Client: registryHTTPClient,
		Credential: auth.StaticCredential(host, auth.Credential{
			Username: "oauth2",
			Password: token,
		}),
	}
	return repo, nil
}

// LoadRegistryConfig builds a RegistryConfig from environment variables.
// REGISTRY_INSECURE: comma-separated list of PlainHTTP hosts.
// REGISTRY_CREDENTIALS_FILE: path to a JSON file mapping host -> token.
func LoadRegistryConfig() *RegistryConfig {
	rc := &RegistryConfig{
		Credentials: make(map[string]string),
	}

	if raw := os.Getenv("REGISTRY_INSECURE"); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				rc.InsecureHosts = append(rc.InsecureHosts, h)
			}
		}
	}

	if path := os.Getenv("REGISTRY_CREDENTIALS_FILE"); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // G703: env var path
		if err == nil {
			var creds map[string]string
			if err := json.Unmarshal(data, &creds); err == nil {
				for host, token := range creds {
					rc.Credentials[host] = token
				}
			}
		}
	}

	return rc
}
