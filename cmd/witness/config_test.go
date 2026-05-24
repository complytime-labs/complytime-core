// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	yamlContent := `
witness:
  name: "test-witness"
  poll_interval: 30s
  verification_timeout: 5m

trusted_publishers:
  - name: github-scanners
    issuer: https://token.actions.githubusercontent.com
    sub: "repo:complytime/*"
    allowed_types: [EvaluationLog, EnforcementLog]

  - name: k8s-services
    issuer: https://kubernetes.default.svc
    sub: "system:serviceaccount:complytime:*"
    allowed_types: [EvaluationLog, EnforcementLog, Policy]
`

	tmpfile, err := os.CreateTemp("", "witness-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpfile.Close()

	// Load config
	config, err := LoadConfig(tmpfile.Name())
	require.NoError(t, err)

	// Verify witness settings
	assert.Equal(t, "test-witness", config.Witness.Name)
	assert.Equal(t, 30*time.Second, config.Witness.PollInterval)
	assert.Equal(t, 5*time.Minute, config.Witness.VerificationTimeout)

	// Verify publishers
	require.Len(t, config.TrustedPublishers, 2)
	assert.Equal(t, "github-scanners", config.TrustedPublishers[0].Name)
	assert.Equal(t, "https://token.actions.githubusercontent.com", config.TrustedPublishers[0].Issuer)
	assert.Equal(t, "repo:complytime/*", config.TrustedPublishers[0].Sub)
	assert.Contains(t, config.TrustedPublishers[0].AllowedTypes, "EvaluationLog")
}

func TestLoadConfig_InvalidPath(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	assert.Error(t, err)
}
