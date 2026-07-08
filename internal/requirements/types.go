// SPDX-License-Identifier: Apache-2.0

package requirements

import "time"

// TargetRow represents a target registration with dimensional metadata.
type TargetRow struct {
	TargetID        string    `json:"target_id"`
	TesseraLogIndex uint64    `json:"tessera_log_index"`
	TargetName      string    `json:"target_name"`
	TargetType      string    `json:"target_type"`
	Technologies    []string  `json:"technologies"`
	Geopolitical    []string  `json:"geopolitical"`
	Sensitivity     []string  `json:"sensitivity"`
	Users           []string  `json:"users"`
	Groups          []string  `json:"groups"`
	RegisteredAt    time.Time `json:"registered_at"`
	RegisteredBy    string    `json:"registered_by"`
}

// TrustedPublisherRow represents an authorized OIDC identity for a target.
type TrustedPublisherRow struct {
	TargetID          string     `json:"target_id"`
	Issuer            string     `json:"issuer"`
	SubPattern        string     `json:"sub_pattern"`
	Environment       *string    `json:"environment,omitempty"`
	AddedAt           time.Time  `json:"added_at"`
	AddedBy           *string    `json:"added_by,omitempty"`
	TesseraLogIndex   *int64     `json:"tessera_log_index,omitempty"`
	RemovedAt         *time.Time `json:"removed_at,omitempty"`
	RemovedByLogIndex *int64     `json:"removed_by_log_index,omitempty"`
}

// TrustedPublisherKey identifies a trusted publisher by issuer and subject pattern.
type TrustedPublisherKey struct {
	Issuer     string
	SubPattern string
}

// OciImportedArtifact describes an artifact imported from an OCI bundle.
type OciImportedArtifact struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}
