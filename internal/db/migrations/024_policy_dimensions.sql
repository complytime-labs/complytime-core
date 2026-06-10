-- SPDX-License-Identifier: Apache-2.0
-- Migration 024: Add dimension and timeline columns to policies table

ALTER TABLE policies ADD COLUMN IF NOT EXISTS technologies TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS geopolitical TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS sensitivity TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS users TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS groups TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_start TIMESTAMPTZ;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_end TIMESTAMPTZ;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS bundle_id TEXT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tessera_log_index BIGINT;

CREATE INDEX IF NOT EXISTS idx_policies_bundle ON policies(bundle_id) WHERE bundle_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policies_timeline ON policies(evaluation_timeline_start, evaluation_timeline_end);

COMMENT ON COLUMN policies.bundle_id IS 'Links policy to OCI bundle for effective policy resolution';
COMMENT ON COLUMN policies.tessera_log_index IS 'Tessera transparency log position';
