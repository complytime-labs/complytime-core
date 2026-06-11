// SPDX-License-Identifier: Apache-2.0

package db

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrConstraint = errors.New("constraint violation")
)

// ClassifyError maps PostgreSQL errors to domain sentinel errors.
// If the error is not a PG error, it is returned unchanged.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	switch pgErr.Code {
	case "23505": // unique_violation
		return errors.Join(ErrConflict, err)
	case "23503": // foreign_key_violation
		return errors.Join(ErrConstraint, err)
	case "23514": // check_violation
		return errors.Join(ErrConstraint, err)
	case "23502": // not_null_violation
		return errors.Join(ErrConstraint, err)
	default:
		return err
	}
}
