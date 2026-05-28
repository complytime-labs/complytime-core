// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Witness           WitnessConfig      `yaml:"witness"`
	TrustedPublishers []TrustedPublisher `yaml:"trusted_publishers"`
}

type WitnessConfig struct {
	Name                string        `yaml:"name"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	VerificationTimeout time.Duration `yaml:"verification_timeout"`
}

type TrustedPublisher struct {
	Name         string   `yaml:"name"`
	Issuer       string   `yaml:"issuer"`
	Sub          string   `yaml:"sub"`           // Glob pattern (e.g., "repo:org/*")
	AllowedTypes []string `yaml:"allowed_types"` // [EvaluationLog, EnforcementLog, Policy, AuditLog]
}

func (c *Config) Validate() error {
	if c.Witness.Name == "" {
		return fmt.Errorf("witness name is required")
	}
	if c.Witness.PollInterval <= 0 {
		return fmt.Errorf("poll_interval must be positive")
	}
	if c.Witness.VerificationTimeout <= c.Witness.PollInterval {
		return fmt.Errorf("verification_timeout must be greater than poll_interval")
	}
	if len(c.TrustedPublishers) == 0 {
		return fmt.Errorf("at least one trusted publisher is required")
	}

	// Validate trusted publishers
	for i, pub := range c.TrustedPublishers {
		if len(pub.AllowedTypes) == 0 {
			return fmt.Errorf("publisher %d (%s): at least one allowed_type is required", i, pub.Name)
		}

		if pub.Sub != "" {
			// Check for unsupported wildcard positions (wildcard must be at end)
			if strings.Contains(pub.Sub, "*") && !strings.HasSuffix(pub.Sub, "*") {
				return fmt.Errorf("publisher %d (%s): wildcard (*) must be at end of pattern, got: %s", i, pub.Name, pub.Sub)
			}
		}
	}

	return nil
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}
