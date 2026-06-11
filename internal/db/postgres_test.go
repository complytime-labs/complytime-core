// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/complytime-labs/complytime-core/internal/auth"
)

// testClient connects to the test database and runs migrations.
// Skips the test if POSTGRES_TEST_URL is not set.
func testClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv("POSTGRES_TEST_URL")
	if url == "" {
		t.Skip("POSTGRES_TEST_URL not set — skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := New(ctx, Config{URL: url})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := c.EnsureSchema(ctx); err != nil {
		c.Close()
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = c.pool.Exec(ctx, "DELETE FROM notifications")
		_, _ = c.pool.Exec(ctx, "DELETE FROM role_changes")
		_, _ = c.pool.Exec(ctx, "DELETE FROM users")
		c.Close()
	})
	return c
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func TestUsers_UpsertAndGet(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.UpsertUser(ctx, "sub-1", "https://idp.example.com", "alice@example.com", "Alice", ""); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	u, err := c.GetUser(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.Sub != "sub-1" || u.Issuer != "https://idp.example.com" {
		t.Fatalf("unexpected sub/issuer: %q / %q", u.Sub, u.Issuer)
	}
	if u.Role != "reviewer" {
		t.Fatalf("expected default role 'reviewer', got %q", u.Role)
	}

	if err := c.UpsertUser(ctx, "sub-1", "https://idp.example.com", "alice@example.com", "Alice Updated", "https://avatar.example.com/a.png"); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	u, _ = c.GetUser(ctx, "alice@example.com")
	if u.Name != "Alice Updated" {
		t.Fatalf("expected updated name, got %q", u.Name)
	}
}

func TestUsers_GetBySub(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.UpsertUser(ctx, "sub-2", "https://idp.example.com", "bob@example.com", "Bob", ""); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	u, err := c.GetUserBySub(ctx, "sub-2", "https://idp.example.com")
	if err != nil {
		t.Fatalf("get by sub: %v", err)
	}
	if u.Email != "bob@example.com" {
		t.Fatalf("expected bob@example.com, got %q", u.Email)
	}

	_, err = c.GetUserBySub(ctx, "nonexistent", "https://idp.example.com")
	if err == nil {
		t.Fatal("expected ErrUserNotFound")
	}
}

func TestUsers_RoleTransitions(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.UpsertUser(ctx, "sub-3", "https://idp.example.com", "carol@example.com", "Carol", ""); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	oldRole, err := c.SetRole(ctx, "carol@example.com", "admin")
	if err != nil {
		t.Fatalf("set role: %v", err)
	}
	if oldRole != "reviewer" {
		t.Fatalf("expected old role 'reviewer', got %q", oldRole)
	}

	u, _ := c.GetUser(ctx, "carol@example.com")
	if u.Role != "admin" {
		t.Fatalf("expected role 'admin', got %q", u.Role)
	}

	count, err := c.CountAdmins(ctx)
	if err != nil {
		t.Fatalf("count admins: %v", err)
	}
	if count < 1 {
		t.Fatal("expected at least 1 admin")
	}

	if err := c.InsertRoleChange(ctx, auth.RoleChange{
		ChangedBy:   "test",
		TargetEmail: "carol@example.com",
		OldRole:     "reviewer",
		NewRole:     "admin",
	}); err != nil {
		t.Fatalf("insert role change: %v", err)
	}

	changes, err := c.ListRoleChanges(ctx)
	if err != nil {
		t.Fatalf("list role changes: %v", err)
	}
	if len(changes) < 1 {
		t.Fatal("expected at least 1 role change")
	}
}

// ---------------------------------------------------------------------------
// Schema migration idempotency
// ---------------------------------------------------------------------------

func TestEnsureSchema_Idempotent(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := c.EnsureSchema(ctx); err != nil {
		t.Fatalf("second EnsureSchema: %v", err)
	}
}
