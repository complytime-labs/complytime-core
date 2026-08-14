package publisher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSPIFFEValidateTrustEntry(t *testing.T) {
	s := &SPIFFEIssuer{url: "https://spire.example.com"}

	valid := []string{
		"spiffe://example.org/workload/scanner",
		"spiffe://trust-domain.example/ns/default/sa/my-service",
		"spiffe://example.org/k8s/cluster1/ns/prod/sa/api",
	}
	invalid := []string{
		"",
		"not-spiffe",
		"spiffe://missing-path",
		"https://example.com/not-spiffe",
		"spiffe:///no-trust-domain",
	}

	for _, sub := range valid {
		assert.NoError(t, s.ValidateTrustEntry(sub), "should accept: %s", sub)
	}
	for _, sub := range invalid {
		assert.Error(t, s.ValidateTrustEntry(sub), "should reject: %s", sub)
	}
}
