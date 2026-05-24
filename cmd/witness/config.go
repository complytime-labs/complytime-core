// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
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

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	return &config, nil
}
