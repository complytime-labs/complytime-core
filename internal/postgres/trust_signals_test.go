// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"
	"time"
)

// TestTrustSignals_Schema verifies the trust_signals table was created correctly.
func TestTrustSignals_Schema(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Verify table exists by querying its structure
	var tableName string
	err := c.pool.QueryRow(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'trust_signals'
	`).Scan(&tableName)
	if err != nil {
		t.Fatalf("trust_signals table not found: %v", err)
	}
	if tableName != "trust_signals" {
		t.Fatalf("expected table 'trust_signals', got %q", tableName)
	}

	// Verify columns exist
	expectedColumns := map[string]string{
		"evidence_id": "text",
		"layer":       "text",
		"check_name":  "text",
		"result":      "text",
		"reason":      "text",
		"checked_at":  "timestamp with time zone",
	}

	rows, err := c.pool.Query(ctx, `
		SELECT column_name, data_type
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'trust_signals'
	`)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer rows.Close()

	foundColumns := make(map[string]string)
	for rows.Next() {
		var colName, dataType string
		if err := rows.Scan(&colName, &dataType); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		foundColumns[colName] = dataType
	}

	for col, typ := range expectedColumns {
		if foundType, ok := foundColumns[col]; !ok {
			t.Errorf("missing column %q", col)
		} else if foundType != typ {
			t.Errorf("column %q: expected type %q, got %q", col, typ, foundType)
		}
	}
}

// TestTrustSignals_InsertAndQuery verifies basic insert and query operations.
func TestTrustSignals_InsertAndQuery(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Clean up before test
	_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-1'")

	// Insert a test signal
	now := time.Now().UTC()
	_, err := c.pool.Exec(ctx, `
		INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, "test-evidence-1", "identity", "publisher_auth", "pass", "Valid signature", now)
	if err != nil {
		t.Fatalf("insert signal: %v", err)
	}

	// Query it back
	var evidenceID, layer, checkName, result, reason string
	var checkedAt time.Time
	err = c.pool.QueryRow(ctx, `
		SELECT evidence_id, layer, check_name, result, reason, checked_at
		FROM trust_signals
		WHERE evidence_id = $1 AND layer = $2 AND check_name = $3
	`, "test-evidence-1", "identity", "publisher_auth").Scan(
		&evidenceID, &layer, &checkName, &result, &reason, &checkedAt,
	)
	if err != nil {
		t.Fatalf("query signal: %v", err)
	}

	if evidenceID != "test-evidence-1" {
		t.Errorf("expected evidence_id 'test-evidence-1', got %q", evidenceID)
	}
	if layer != "identity" {
		t.Errorf("expected layer 'identity', got %q", layer)
	}
	if checkName != "publisher_auth" {
		t.Errorf("expected check_name 'publisher_auth', got %q", checkName)
	}
	if result != "pass" {
		t.Errorf("expected result 'pass', got %q", result)
	}
	if reason != "Valid signature" {
		t.Errorf("expected reason 'Valid signature', got %q", reason)
	}

	// Cleanup
	_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-1'")
}

// TestTrustSignals_Constraints verifies CHECK constraints work.
func TestTrustSignals_Constraints(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Test invalid layer
	_, err := c.pool.Exec(ctx, `
		INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason)
		VALUES ($1, $2, $3, $4, $5)
	`, "test-evidence-2", "invalid_layer", "schema", "pass", "")
	if err == nil {
		t.Error("expected error for invalid layer, got nil")
		_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-2'")
	}

	// Test invalid result
	_, err = c.pool.Exec(ctx, `
		INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason)
		VALUES ($1, $2, $3, $4, $5)
	`, "test-evidence-3", "quality", "schema", "invalid_result", "")
	if err == nil {
		t.Error("expected error for invalid result, got nil")
		_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-3'")
	}
}

// TestTrustSignals_PrimaryKey verifies composite primary key enforcement.
func TestTrustSignals_PrimaryKey(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Clean up before test
	_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-4'")

	// Insert first signal
	_, err := c.pool.Exec(ctx, `
		INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason)
		VALUES ($1, $2, $3, $4, $5)
	`, "test-evidence-4", "quality", "schema", "pass", "Valid")
	if err != nil {
		t.Fatalf("insert first signal: %v", err)
	}

	// Try to insert duplicate (same evidence_id, layer, check_name)
	_, err = c.pool.Exec(ctx, `
		INSERT INTO trust_signals (evidence_id, layer, check_name, result, reason)
		VALUES ($1, $2, $3, $4, $5)
	`, "test-evidence-4", "quality", "schema", "fail", "Invalid")
	if err == nil {
		t.Error("expected primary key violation, got nil")
	}

	// Cleanup
	_, _ = c.pool.Exec(ctx, "DELETE FROM trust_signals WHERE evidence_id = 'test-evidence-4'")
}

// TestTrustSignals_Indexes verifies indexes exist for common query patterns.
func TestTrustSignals_Indexes(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Query pg_indexes to verify our indexes exist
	expectedIndexes := []string{
		"trust_signals_pkey",            // Primary key
		"idx_trust_signals_result",      // (evidence_id, result)
		"idx_trust_signals_layer",       // (layer, check_name, result)
	}

	for _, idxName := range expectedIndexes {
		var exists bool
		err := c.pool.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM pg_indexes
				WHERE schemaname = 'public'
				AND tablename = 'trust_signals'
				AND indexname = $1
			)
		`, idxName).Scan(&exists)
		if err != nil {
			t.Fatalf("query index %q: %v", idxName, err)
		}
		if !exists {
			t.Errorf("expected index %q to exist", idxName)
		}
	}
}
