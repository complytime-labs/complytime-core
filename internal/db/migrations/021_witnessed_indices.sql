-- SPDX-License-Identifier: Apache-2.0
-- Migration 021: Create witnessed_indices table for witness service

-- Track which Tessera log indices have been verified and countersigned by witness
CREATE TABLE IF NOT EXISTS witnessed_indices (
    log_index BIGINT PRIMARY KEY,
    witnessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    witness_name TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL
);

-- Index for timestamp-based queries (e.g., recent witnessed entries)
CREATE INDEX IF NOT EXISTS idx_witnessed_indices_timestamp ON witnessed_indices(witnessed_at DESC);

-- Add descriptive comment
COMMENT ON TABLE witnessed_indices IS 'Tracks Tessera log indices that have been verified and countersigned by the witness service';
