// SPDX-License-Identifier: Apache-2.0

package purl_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/purl"
)

func TestIsPURL(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"pkg:generic/acme/prod-cluster@v1", true},
		{"pkg:oci/myapp@sha256:abc123", true},
		{"prod-cluster", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := purl.IsPURL(tt.id); got != tt.want {
			t.Errorf("IsPURL(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		{"pkg:generic/acme/prod-cluster@v1", false},
		{"pkg:oci/myapp@sha256:abc123", false},
		{"pkg:golang/github.com/example/repo@v1.0.0", false},
		{"pkg:npm/@scope/package@1.0.0", false},
		{"prod-cluster", false},
		{"", false},
		{"pkg:", true},
		{"pkg:///", true},
	}
	for _, tt := range tests {
		err := purl.Validate(tt.id)
		if (err != nil) != tt.wantErr {
			t.Errorf("Validate(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"pkg:Generic/Acme/Prod-Cluster@v1", "pkg:generic/Acme/Prod-Cluster@v1"},
		{"pkg:golang/github.com/Example/Repo@v1.0.0", "pkg:golang/github.com/example/repo@v1.0.0"},
		{"prod-cluster", "prod-cluster"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := purl.Normalize(tt.id); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
