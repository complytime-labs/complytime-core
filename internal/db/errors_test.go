// SPDX-License-Identifier: Apache-2.0

package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestClassifyError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		{"no rows", pgx.ErrNoRows, ErrNotFound},
		{"wrapped no rows", fmt.Errorf("get policy: %w", pgx.ErrNoRows), ErrNotFound},
		{"unique violation", &pgconn.PgError{Code: "23505"}, ErrConflict},
		{"foreign key", &pgconn.PgError{Code: "23503"}, ErrConstraint},
		{"check violation", &pgconn.PgError{Code: "23514"}, ErrConstraint},
		{"not null", &pgconn.PgError{Code: "23502"}, ErrConstraint},
		{"other pg error", &pgconn.PgError{Code: "42P01"}, nil},  // table not found, not classified
		{"generic error", errors.New("connection refused"), nil}, // unchanged
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if tt.want == nil {
				if tt.err == nil && result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				// For non-classified errors, the original is returned unchanged
				return
			}
			if !errors.Is(result, tt.want) {
				t.Errorf("ClassifyError(%v) = %v, want errors.Is(%v)", tt.err, result, tt.want)
			}
		})
	}
}
