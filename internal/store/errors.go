// SPDX-License-Identifier: Apache-2.0

package store

import "github.com/complytime-labs/complytime-core/internal/db"

// Re-export db sentinel errors for handler use.
var (
	ErrNotFound   = db.ErrNotFound
	ErrConflict   = db.ErrConflict
	ErrConstraint = db.ErrConstraint
)

// classifyErr wraps a database error with the appropriate sentinel.
func classifyErr(err error) error {
	return db.ClassifyError(err)
}
