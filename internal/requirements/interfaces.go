// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"context"
	"time"

	"github.com/complytime-labs/complytime-core/internal/gemara"
)

// PolicyStore defines read/write operations for policy artifacts.
type PolicyStore interface {
	InsertPolicy(ctx context.Context, p Policy) error
	ListPolicies(ctx context.Context) ([]Policy, error)
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
}

// MappingStore defines read/write operations for crosswalk mappings.
type MappingStore interface {
	InsertMapping(ctx context.Context, m MappingDocument) error
	ListMappings(ctx context.Context, policyID string) ([]MappingDocument, error)
	ListAllMappings(ctx context.Context) ([]MappingDocument, error)
	QueryMappings(ctx context.Context, sourceCatalogID, targetCatalogID string, limit int) ([]gemara.MappingEntry, error)
	InsertMappingEntries(ctx context.Context, entries []gemara.MappingEntry) error
	DeleteMappingEntries(ctx context.Context, sourceCatalogID, targetCatalogID string) error
	CountMappingEntries(ctx context.Context, mappingID string) (int, error)
}

// GuidanceStore defines write operations for parsed guidance catalog entries.
type GuidanceStore interface {
	InsertGuidanceEntries(ctx context.Context, rows []gemara.GuidanceEntryRow) error
}

// ControlStore defines read/write operations for parsed control catalog entries.
type ControlStore interface {
	InsertControls(ctx context.Context, rows []gemara.ControlRow) error
	InsertAssessmentRequirements(ctx context.Context, rows []gemara.AssessmentRequirementRow) error
	InsertControlThreats(ctx context.Context, rows []gemara.ControlThreatRow) error
	CountControls(ctx context.Context, catalogID string) (int, error)
}

// ThreatStore defines read/write operations for parsed threat catalog entries.
type ThreatStore interface {
	InsertThreats(ctx context.Context, rows []gemara.ThreatRow) error
	CountThreats(ctx context.Context, catalogID string) (int, error)
	QueryThreats(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.ThreatRow, error)
	QueryControlThreats(ctx context.Context, catalogID, controlID string, limit int) ([]gemara.ControlThreatRow, error)
}

// RiskStore defines read/write operations for parsed risk catalog entries.
type RiskStore interface {
	InsertRisks(ctx context.Context, rows []gemara.RiskRow) error
	InsertRiskThreats(ctx context.Context, rows []gemara.RiskThreatRow) error
	CountRisks(ctx context.Context, catalogID string) (int, error)
	QueryRisks(ctx context.Context, catalogID, policyID string, limit int) ([]gemara.RiskRow, error)
	QueryRiskThreats(ctx context.Context, catalogID, riskID string, limit int) ([]gemara.RiskThreatRow, error)
}

// CatalogStore defines read/write operations for raw catalog artifacts.
type CatalogStore interface {
	InsertCatalog(ctx context.Context, c Catalog) error
	ListCatalogs(ctx context.Context) ([]Catalog, error)
	GetCatalog(ctx context.Context, catalogID string) (*Catalog, error)
}

// TargetStore defines operations for target registrations.
type TargetStore interface {
	InsertTarget(ctx context.Context, t TargetRow) error
	GetLatestTarget(ctx context.Context, targetID string, asOf time.Time) (*TargetRow, error)
	ListTargets(ctx context.Context) ([]TargetRow, error)
}

// TrustedPublisherStore defines operations for target-scoped publisher authorizations.
type TrustedPublisherStore interface {
	InsertTrustedPublishers(ctx context.Context, rows []TrustedPublisherRow) error
	GetTrustedPublishers(ctx context.Context, targetID string) ([]TrustedPublisherRow, error)
	RemoveTrustedPublishers(ctx context.Context, targetID string, keys []TrustedPublisherKey, logIndex uint64) error
}

// PolicyDimensionStore defines queries for policies with dimension matching.
type PolicyDimensionStore interface {
	QueryPoliciesByDimensions(ctx context.Context, dims DimensionQuery) ([]PolicyWithDimensions, error)
}
