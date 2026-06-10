// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Config holds PostgreSQL connection parameters.
type Config struct {
	URL string // Full connection string, e.g. postgres://user:pass@host:5432/studio
}

// ConfigFromEnv builds Config from the POSTGRES_URL env var.
// Returns ok=false when the variable is empty; the gateway treats this as fatal.
func ConfigFromEnv() (Config, bool) {
	url := os.Getenv("POSTGRES_URL")
	if url == "" {
		return Config{}, false
	}
	return Config{URL: url}, true
}

// Client wraps a pgxpool.Pool and provides schema migration.
type Client struct {
	pool *pgxpool.Pool
}

// Pool tuning defaults. Override via env: PG_MAX_CONNS, PG_MAX_CONN_LIFETIME,
// PG_MAX_CONN_IDLE_TIME, PG_STATEMENT_TIMEOUT.
var (
	defaultMaxConns         int32         = 10
	defaultMaxConnLifetime  time.Duration = 30 * time.Minute
	defaultMaxConnIdleTime  time.Duration = 5 * time.Minute
	defaultStatementTimeout               = "30s"
)

// New creates a connection pool and verifies connectivity.
// Pool limits are configurable via environment variables.
func New(ctx context.Context, cfg Config) (*Client, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("postgres parse config: %w", err)
	}

	poolCfg.MaxConns = envInt32("PG_MAX_CONNS", defaultMaxConns)
	poolCfg.MaxConnLifetime = envDuration("PG_MAX_CONN_LIFETIME", defaultMaxConnLifetime)
	poolCfg.MaxConnIdleTime = envDuration("PG_MAX_CONN_IDLE_TIME", defaultMaxConnIdleTime)

	if timeout := envString("PG_STATEMENT_TIMEOUT", defaultStatementTimeout); timeout != "" {
		if poolCfg.ConnConfig.RuntimeParams == nil {
			poolCfg.ConnConfig.RuntimeParams = make(map[string]string)
		}
		poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = timeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}

	slog.Info("postgres pool configured",
		"max_conns", poolCfg.MaxConns,
		"max_lifetime", poolCfg.MaxConnLifetime,
		"max_idle_time", poolCfg.MaxConnIdleTime,
	)
	return &Client{pool: pool}, nil
}

func envInt32(key string, fallback int32) int32 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(n)
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ensureSchemaWith runs migrations using a separate connection URL.
func (c *Client) ensureSchemaWith(ctx context.Context, url string) error {
	migCfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parse migration url: %w", err)
	}
	migCfg.MaxConns = 1
	migPool, err := pgxpool.NewWithConfig(ctx, migCfg)
	if err != nil {
		return fmt.Errorf("migration connect: %w", err)
	}
	defer migPool.Close()

	conn, err := migPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migration: %w", err)
	}
	defer conn.Release()
	return runMigrations(ctx, conn)
}

// Pool returns the underlying connection pool for direct use by store implementations.
func (c *Client) Pool() *pgxpool.Pool {
	return c.pool
}

// Ping verifies the database connection is alive.
func (c *Client) Ping(ctx context.Context) error {
	return c.pool.Ping(ctx)
}

// Close releases the connection pool.
func (c *Client) Close() {
	c.pool.Close()
}

// EnsureSchema applies all embedded SQL migrations in order.
// Uses an advisory lock to prevent concurrent migration runs and a
// schema_migrations table to track applied versions.
//
// When POSTGRES_MIGRATION_URL is set, migrations run against that URL
// (typically a superuser) instead of the runtime pool. This supports
// least-privilege runtime roles (e.g. gateway_rw) that lack CREATE/ALTER.
func (c *Client) EnsureSchema(ctx context.Context) error {
	migrationURL := os.Getenv("POSTGRES_MIGRATION_URL")
	if migrationURL != "" {
		return c.ensureSchemaWith(ctx, migrationURL)
	}
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migration: %w", err)
	}
	defer conn.Release()
	return runMigrations(ctx, conn)
}

// runMigrations applies embedded SQL migrations using the given connection.
func runMigrations(ctx context.Context, conn *pgxpool.Conn) error {
	const lockID int64 = 0x5354554449_4F5047 // "STUDIO_PG"
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version  INTEGER PRIMARY KEY,
			filename TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		version, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("migration %s: cannot parse version from filename: %w", entry.Name(), err)
		}

		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists {
			continue
		}

		sql, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		slog.Info("applying postgres migration", "version", version, "file", entry.Name())
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %d (%s): %w", version, entry.Name(), err)
		}

		if _, err := conn.Exec(ctx, "INSERT INTO schema_migrations (version, filename) VALUES ($1, $2)", version, entry.Name()); err != nil {
			return fmt.Errorf("record migration %d: %w", version, err)
		}
	}
	return nil
}
