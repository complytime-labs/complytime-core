// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
)

type TesseraReader interface {
	Read(ctx context.Context, index uint64) ([]byte, error)
}

type PostgresQuerier interface {
	QueryEvidenceByLogIndex(ctx context.Context, logIndex uint64) (*EvidenceRow, error)
}

type EvidenceRow struct {
	Certified       bool
	PublisherIssuer string
	SubmittedBy     string
}

type Verifier struct {
	tessera TesseraReader
	db      PostgresQuerier
	config  *Config
}

func NewVerifier(tessera TesseraReader, db PostgresQuerier, config *Config) *Verifier {
	return &Verifier{
		tessera: tessera,
		db:      db,
		config:  config,
	}
}

func (v *Verifier) VerifyEntry(ctx context.Context, logIndex uint64) bool {
	// 1. Fetch entry from Tessera
	entry, err := v.tessera.Read(ctx, logIndex)
	if err != nil {
		slog.Error("failed to read entry from Tessera", "log_index", logIndex, "error", err)
		return false
	}

	// 2. Parse Gemara artifact type
	artifactType, err := parseGemaraType(entry)
	if err != nil {
		slog.Error("invalid Gemara artifact", "log_index", logIndex, "error", err)
		return false
	}

	// 3. Query PostgreSQL for certification result
	evidenceRow, err := v.db.QueryEvidenceByLogIndex(ctx, logIndex)
	if err != nil {
		slog.Warn("entry not yet in PostgreSQL", "log_index", logIndex, "error", err)
		return false
	}

	// Check entry exists in database
	if evidenceRow == nil {
		slog.Warn("entry not yet in PostgreSQL", "log_index", logIndex)
		return false
	}

	// 4. Check certification passed
	if !evidenceRow.Certified {
		slog.Warn("entry failed certification", "log_index", logIndex)
		return false
	}

	// 5. Verify publisher identity
	if !v.isPublisherTrusted(evidenceRow.PublisherIssuer, evidenceRow.SubmittedBy, artifactType) {
		slog.Warn("publisher not trusted",
			"log_index", logIndex,
			"issuer", evidenceRow.PublisherIssuer,
			"sub", evidenceRow.SubmittedBy)
		return false
	}

	return true
}

func (v *Verifier) isPublisherTrusted(issuer, sub, artifactType string) bool {
	for _, pub := range v.config.TrustedPublishers {
		// Check issuer matches
		if pub.Issuer != issuer {
			continue
		}

		// Check sub matches (glob pattern)
		if !globMatch(pub.Sub, sub) {
			continue
		}

		// Check artifact type allowed
		for _, allowedType := range pub.AllowedTypes {
			if allowedType == artifactType {
				return true
			}
		}
	}

	return false
}

// globMatch performs simple glob pattern matching where * matches any sequence of characters
// This differs from filepath.Match in that * matches across path separators
func globMatch(pattern, text string) bool {
	// Handle exact match
	if pattern == text {
		return true
	}

	// Handle patterns ending with * (most common case for publisher sub patterns)
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(text, prefix)
	}

	// For other patterns, exact match only
	return false
}

func parseGemaraType(entry []byte) (string, error) {
	var metadata struct {
		Metadata struct {
			Type string `yaml:"type"`
		} `yaml:"metadata"`
	}

	if err := yaml.Unmarshal(entry, &metadata); err != nil {
		return "", fmt.Errorf("parse YAML: %w", err)
	}

	if metadata.Metadata.Type == "" {
		return "", fmt.Errorf("missing metadata.type")
	}

	return metadata.Metadata.Type, nil
}
