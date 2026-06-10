-- SPDX-License-Identifier: Apache-2.0
-- Migration 019: Add Tessera log_index to evidence table

-- Add log_index column (nullable for backward compatibility with pre-Tessera evidence)
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS log_index BIGINT;

-- Index for efficient lookup by log_index
CREATE INDEX IF NOT EXISTS idx_evidence_log_index ON evidence(log_index);

-- Add descriptive comment
COMMENT ON COLUMN evidence.log_index IS 'Tessera transparency log position (NULL for pre-Tessera evidence)';
