// SPDX-License-Identifier: Apache-2.0

package requirements

import "time"

// Policy represents a stored policy artifact.
type Policy struct {
	PolicyID     string    `json:"policy_id"`
	Title        string    `json:"title"`
	Version      string    `json:"version,omitempty"`
	OCIReference string    `json:"oci_reference"`
	Content      string    `json:"content"`
	ImportedAt   time.Time `json:"imported_at"`
	ImportedBy   string    `json:"imported_by,omitempty"`

	// Dimensional metadata for policy enrollment
	Technologies            []string   `json:"technologies,omitempty"`
	Geopolitical            []string   `json:"geopolitical,omitempty"`
	Sensitivity             []string   `json:"sensitivity,omitempty"`
	Users                   []string   `json:"users,omitempty"`
	Groups                  []string   `json:"groups,omitempty"`
	EvaluationTimelineStart *time.Time `json:"evaluation_timeline_start,omitempty"`
	EvaluationTimelineEnd   *time.Time `json:"evaluation_timeline_end,omitempty"`
	BundleID                string     `json:"bundle_id,omitempty"`
	TesseraLogIndex         *uint64    `json:"tessera_log_index,omitempty"`
}

// MappingDocument represents a global crosswalk mapping artifact.
type MappingDocument struct {
	MappingID       string    `json:"mapping_id"`
	SourceCatalogID string    `json:"source_catalog_id"`
	TargetCatalogID string    `json:"target_catalog_id"`
	Framework       string    `json:"framework"`
	Content         string    `json:"content"`
	ImportedAt      time.Time `json:"imported_at"`
}

// Catalog represents a stored catalog artifact (ControlCatalog, ThreatCatalog, etc.).
type Catalog struct {
	CatalogID   string    `json:"catalog_id"`
	CatalogType string    `json:"catalog_type"`
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	PolicyID    string    `json:"policy_id,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
}

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
	TargetID        string    `json:"target_id"`
	Issuer          string    `json:"issuer"`
	SubPattern      string    `json:"sub_pattern"`
	Environment     *string   `json:"environment,omitempty"`
	AddedAt         time.Time `json:"added_at"`
	AddedBy         *string   `json:"added_by,omitempty"`
	TesseraLogIndex *int64    `json:"tessera_log_index,omitempty"`
}

// BundleArtifactRow represents an artifact within an OCI bundle.
type BundleArtifactRow struct {
	BundleID        string
	TesseraLogIndex uint64
	ArtifactType    string
	ArtifactID      string
	OCIReference    string
}

// DimensionQuery holds parameters for dimension-based policy matching.
type DimensionQuery struct {
	Technologies []string
	Geopolitical []string
	Sensitivity  []string
	Users        []string
	Groups       []string
	Timestamp    time.Time
}

// PolicyWithDimensions represents a policy with its dimensional metadata.
type PolicyWithDimensions struct {
	LogIndex        uint64    `json:"log_index"`
	PolicyID        string    `json:"policy_id"`
	Title           string    `json:"title"`
	Version         string    `json:"version,omitempty"`
	Technologies    []string  `json:"technologies,omitempty"`
	Geopolitical    []string  `json:"geopolitical,omitempty"`
	Sensitivity     []string  `json:"sensitivity,omitempty"`
	EvaluationStart time.Time `json:"evaluation_start,omitempty"`
	EvaluationEnd   time.Time `json:"evaluation_end,omitempty"`
}

// PolicyQueryResponse is returned by the policy discovery endpoint.
type PolicyQueryResponse struct {
	Target             TargetSummary          `json:"target"`
	ApplicablePolicies []PolicyWithDimensions `json:"applicable_policies"`
}

// TargetSummary is a brief target representation in API responses.
type TargetSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Technologies []string `json:"technologies,omitempty"`
	Geopolitical []string `json:"geopolitical,omitempty"`
	Sensitivity  []string `json:"sensitivity,omitempty"`
	RegisteredAt string   `json:"registered_at"`
}

// OciImportedArtifact describes an artifact imported from an OCI bundle.
type OciImportedArtifact struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// PolicyIngestOption carries Tessera provenance data for async-ingested policies.
type PolicyIngestOption struct {
	LogIndex uint64
	BundleID string
}
