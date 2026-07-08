// SPDX-License-Identifier: Apache-2.0

package requirements

import (
	"context"
	"time"
)

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
