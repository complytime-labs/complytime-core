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
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	_, err = tmpfile.WriteString(yamlContent)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

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

func TestConfig_Validate_MissingWitnessName(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com", AllowedTypes: []string{"EvaluationLog"}},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "witness name is required")
}

func TestConfig_Validate_InvalidPollInterval(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        0,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com", AllowedTypes: []string{"EvaluationLog"}},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "poll_interval must be positive")
}

func TestConfig_Validate_NegativePollInterval(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        -1 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com", AllowedTypes: []string{"EvaluationLog"}},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "poll_interval must be positive")
}

func TestConfig_Validate_TimeoutNotGreaterThanInterval(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 30 * time.Second,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com", AllowedTypes: []string{"EvaluationLog"}},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification_timeout must be greater than poll_interval")
}

func TestConfig_Validate_EmptyPublishers(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one trusted publisher is required")
}

func TestConfig_Validate_Valid(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test", Issuer: "https://example.com", AllowedTypes: []string{"EvaluationLog"}},
		},
	}
	err := config.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_EmptyAllowedTypes(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{Name: "test-publisher", Issuer: "https://example.com", AllowedTypes: []string{}},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one allowed_type is required")
}

func TestConfig_Validate_InvalidWildcardPosition(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{
				Name:         "test-publisher",
				Issuer:       "https://example.com",
				Sub:          "repo:*/scanner",
				AllowedTypes: []string{"EvaluationLog"},
			},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard (*) must be at end of pattern")
}

func TestConfig_Validate_ValidWildcardAtEnd(t *testing.T) {
	config := &Config{
		Witness: WitnessConfig{
			Name:                "test-witness",
			PollInterval:        30 * time.Second,
			VerificationTimeout: 5 * time.Minute,
		},
		TrustedPublishers: []TrustedPublisher{
			{
				Name:         "test-publisher",
				Issuer:       "https://example.com",
				Sub:          "repo:complytime/*",
				AllowedTypes: []string{"EvaluationLog"},
			},
		},
	}
	err := config.Validate()
	assert.NoError(t, err)
}
