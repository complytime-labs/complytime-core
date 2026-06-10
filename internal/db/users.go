// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/consts"
)

var _ auth.UserStore = (*Client)(nil)

func (c *Client) UpsertUser(ctx context.Context, sub, issuer, email, name, avatarURL string) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO users (sub, issuer, email, name, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (email) DO UPDATE SET
			sub = EXCLUDED.sub,
			issuer = EXCLUDED.issuer,
			name = EXCLUDED.name,
			avatar_url = EXCLUDED.avatar_url`,
		sub, issuer, email, name, avatarURL,
	)
	if err != nil {
		return fmt.Errorf("upsert user %s: %w", email, err)
	}
	return nil
}

func (c *Client) GetUser(ctx context.Context, email string) (*auth.User, error) {
	row := c.pool.QueryRow(ctx, `
		SELECT sub, issuer, email, name, avatar_url, role, created_at
		FROM users WHERE email = $1`, email)
	var u auth.User
	if err := row.Scan(&u.Sub, &u.Issuer, &u.Email, &u.Name, &u.AvatarURL, &u.Role, &u.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("get user %s: %w", email, auth.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user %s: %w", email, err)
	}
	return &u, nil
}

func (c *Client) GetUserBySub(ctx context.Context, sub, issuer string) (*auth.User, error) {
	row := c.pool.QueryRow(ctx, `
		SELECT sub, issuer, email, name, avatar_url, role, created_at
		FROM users WHERE sub = $1 AND issuer = $2`, sub, issuer)
	var u auth.User
	if err := row.Scan(&u.Sub, &u.Issuer, &u.Email, &u.Name, &u.AvatarURL, &u.Role, &u.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("get user (sub=%s issuer=%s): %w", sub, issuer, auth.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user by sub: %w", err)
	}
	return &u, nil
}

func (c *Client) ListUsers(ctx context.Context) ([]auth.User, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT sub, issuer, email, name, avatar_url, role, created_at
		FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []auth.User
	for rows.Next() {
		var u auth.User
		if err := rows.Scan(&u.Sub, &u.Issuer, &u.Email, &u.Name, &u.AvatarURL, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (c *Client) SetRole(ctx context.Context, email, role string) (string, error) {
	var oldRole string
	err := c.pool.QueryRow(ctx, `
		WITH prev AS (
			SELECT role FROM users WHERE email = $2
		)
		UPDATE users SET role = $1
		WHERE email = $2
		RETURNING (SELECT role FROM prev)`,
		role, email,
	).Scan(&oldRole)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("set role: user %s not found: %w", email, auth.ErrUserNotFound)
		}
		return "", fmt.Errorf("set role for %s: %w", email, err)
	}
	return oldRole, nil
}

func (c *Client) CountUsers(ctx context.Context) (int, error) {
	var count int
	if err := c.pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (c *Client) CountAdmins(ctx context.Context) (int, error) {
	var count int
	if err := c.pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE role = $1", consts.RoleAdmin).Scan(&count); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return count, nil
}

func (c *Client) InsertRoleChange(ctx context.Context, change auth.RoleChange) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO role_changes (changed_by, target_email, old_role, new_role)
		VALUES ($1, $2, $3, $4)`,
		change.ChangedBy, change.TargetEmail, change.OldRole, change.NewRole,
	)
	if err != nil {
		return fmt.Errorf("insert role change: %w", err)
	}
	return nil
}

// BootstrapAdmin atomically promotes email to admin if and only if no admin
// exists. Uses a CTE with a conditional UPDATE in a single statement,
// eliminating the TOCTOU race in the two-step check-then-promote pattern.
// Returns ErrAdminExists if an admin already exists, or ErrUserNotFound if
// the target email has no user record.
func (c *Client) BootstrapAdmin(ctx context.Context, email string) (string, error) {
	var oldRole string
	err := c.pool.QueryRow(ctx, `
		WITH snap AS (
			SELECT role FROM users WHERE email = $1
		), guard AS (
			SELECT count(*) AS cnt FROM users WHERE role = 'admin'
		)
		UPDATE users SET role = 'admin'
		FROM guard
		WHERE guard.cnt = 0 AND users.email = $1
		RETURNING (SELECT role FROM snap)`, email).Scan(&oldRole)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("bootstrap admin: %w", err)
		}
		n, countErr := c.CountAdmins(ctx)
		if countErr != nil {
			return "", fmt.Errorf("bootstrap admin: %w", countErr)
		}
		if n > 0 {
			return "", auth.ErrAdminExists
		}
		return "", fmt.Errorf("bootstrap admin for %s: %w", email, auth.ErrUserNotFound)
	}
	return oldRole, nil
}

func (c *Client) ListRoleChanges(ctx context.Context) ([]auth.RoleChange, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT changed_by, target_email, old_role, new_role, changed_at
		FROM role_changes ORDER BY changed_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list role changes: %w", err)
	}
	defer rows.Close()

	var changes []auth.RoleChange
	for rows.Next() {
		var ch auth.RoleChange
		if err := rows.Scan(&ch.ChangedBy, &ch.TargetEmail, &ch.OldRole, &ch.NewRole, &ch.ChangedAt); err != nil {
			return nil, err
		}
		changes = append(changes, ch)
	}
	return changes, rows.Err()
}
