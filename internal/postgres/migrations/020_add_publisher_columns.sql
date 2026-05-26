-- SPDX-License-Identifier: Apache-2.0
-- Migration 020: Add publisher identity columns to evidence table

-- Add publisher columns (nullable for backward compatibility with pre-Tessera evidence)
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS publisher_issuer TEXT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS submitted_by TEXT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS publisher_type TEXT;

-- Index for efficient publisher queries
CREATE INDEX IF NOT EXISTS idx_evidence_publisher ON evidence(publisher_issuer, submitted_by);

-- Add descriptive comments
COMMENT ON COLUMN evidence.publisher_issuer IS 'JWT issuer claim (e.g., https://token.actions.githubusercontent.com)';
COMMENT ON COLUMN evidence.submitted_by IS 'JWT subject claim (e.g., repo:org/name:ref:refs/heads/main)';
COMMENT ON COLUMN evidence.publisher_type IS 'Inferred publisher type: pipeline, service, or unknown';
