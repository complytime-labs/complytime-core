// SPDX-License-Identifier: Apache-2.0

package targetid_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/targetid"
)

func TestIsPURL(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"pkg:generic/acme/prod-cluster@v1", true},
		{"pkg:oci/myapp@sha256:abc123", true},
		{"cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*", false},
		{"prod-cluster", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := targetid.IsPURL(tt.id); got != tt.want {
			t.Errorf("IsPURL(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestIsCPE(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*", true},
		{"cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*", true},
		{"pkg:generic/acme/prod-cluster@v1", false},
		{"prod-cluster", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := targetid.IsCPE(tt.id); got != tt.want {
			t.Errorf("IsCPE(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		// PURLs
		{"pkg:generic/acme/prod-cluster@v1", false},
		{"pkg:oci/myapp@sha256:abc123", false},
		{"pkg:golang/github.com/example/repo@v1.0.0", false},
		{"pkg:npm/@scope/package@1.0.0", false},
		{"pkg:", true},
		{"pkg:///", true},
		// CPEs
		{"cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*", false},
		{"cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*", false},
		{"cpe:2.3:bad", true},
		// Plain IDs
		{"prod-cluster", false},
		{"", false},
	}
	for _, tt := range tests {
		err := targetid.Validate(tt.id)
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
		// PURLs — type is lowercased, namespace/name per type-specific rules
		{"pkg:Generic/Acme/Prod-Cluster@v1", "pkg:generic/Acme/Prod-Cluster@v1"},
		{"pkg:golang/github.com/Example/Repo@v1.0.0", "pkg:golang/github.com/example/repo@v1.0.0"},
		// CPEs — round-trip through WFN preserves canonical form
		{"cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*", "cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*"},
		// Plain IDs — passthrough
		{"prod-cluster", "prod-cluster"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := targetid.Normalize(tt.id); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
