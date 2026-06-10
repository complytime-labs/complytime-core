-- SPDX-License-Identifier: Apache-2.0
-- Migration 004: guidance_entries table + global mapping refactor
--
-- Precondition: mapping_entries has policy_id (from 005). This migration
-- adds catalog ID columns, backfills from mapping_documents, then drops
-- policy_id and reshapes the primary key. Ordering matters.

CREATE TABLE IF NOT EXISTS guidance_entries (
    catalog_id   TEXT NOT NULL,
    guideline_id TEXT NOT NULL,
    title        TEXT NOT NULL,
    objective    TEXT NOT NULL DEFAULT '',
    group_id     TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL DEFAULT 'Active',
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_guidance_entries PRIMARY KEY (catalog_id, guideline_id)
);
CREATE INDEX IF NOT EXISTS idx_guidance_entries_catalog ON guidance_entries(catalog_id);

-- Step 1: Add new columns to mapping_documents (keep policy_id until backfill).
ALTER TABLE mapping_documents
    ADD COLUMN IF NOT EXISTS source_catalog_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_catalog_id TEXT NOT NULL DEFAULT '';

-- Step 2: Backfill mapping_documents catalog IDs from framework + policy_id.
-- Pre-production: framework becomes source, policy_id becomes target.
UPDATE mapping_documents SET
    source_catalog_id = COALESCE(NULLIF(framework, ''), 'unknown'),
    target_catalog_id = COALESCE(NULLIF(policy_id, ''), 'unknown')
WHERE source_catalog_id = '' OR target_catalog_id = '';

-- Step 3: Drop policy_id from mapping_documents after backfill.
ALTER TABLE mapping_documents DROP COLUMN IF EXISTS policy_id;
DROP INDEX IF EXISTS idx_mapping_documents_policy;
CREATE INDEX IF NOT EXISTS idx_mapping_documents_catalogs ON mapping_documents(source_catalog_id, target_catalog_id);

-- Step 4: Add guideline_id and catalog columns to mapping_entries BEFORE PK change.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mapping_entries' AND column_name = 'guideline_id'
    ) THEN
        ALTER TABLE mapping_entries ADD COLUMN guideline_id TEXT NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mapping_entries' AND column_name = 'source_catalog_id'
    ) THEN
        ALTER TABLE mapping_entries ADD COLUMN source_catalog_id TEXT NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mapping_entries' AND column_name = 'target_catalog_id'
    ) THEN
        ALTER TABLE mapping_entries ADD COLUMN target_catalog_id TEXT NOT NULL DEFAULT '';
    END IF;
END $$;

-- Step 5: Backfill mapping_entries from existing data.
-- guideline_id = old control_id (which stored m.Source = source entry reference).
-- For guidance crosswalks, m.Source IS the guideline id.
-- For legacy control->assessment crosswalks, m.Source is a control id (harmless:
-- no guidance_entries will match, so guidance coverage returns empty).
UPDATE mapping_entries SET guideline_id = control_id WHERE guideline_id = '';

-- Backfill catalog IDs from the parent mapping_documents row.
UPDATE mapping_entries me SET
    source_catalog_id = COALESCE(md.source_catalog_id, COALESCE(NULLIF(me.framework, ''), 'unknown')),
    target_catalog_id = COALESCE(md.target_catalog_id, COALESCE(NULLIF(me.policy_id, ''), 'unknown'))
FROM mapping_documents md
WHERE md.mapping_id = me.mapping_id
  AND (me.source_catalog_id = '' OR me.target_catalog_id = '');

-- Catch any orphans not linked to a mapping_documents row.
UPDATE mapping_entries SET
    source_catalog_id = COALESCE(NULLIF(framework, ''), 'unknown')
WHERE source_catalog_id = '';
UPDATE mapping_entries SET
    target_catalog_id = COALESCE(NULLIF(policy_id, ''), 'unknown')
WHERE target_catalog_id = '';

-- Realign control_id to target entry reference for existing rows.
-- After parser fix, new rows store control_id = t.EntryId (target control).
-- Old rows stored control_id = m.Source (source entry). Swap to reference
-- (which stored t.EntryId) for consistency. Safe: reference is never NULL.
UPDATE mapping_entries SET control_id = reference
WHERE control_id != reference AND reference != '';

-- Step 6: Now safe to reshape the primary key.
ALTER TABLE mapping_entries DROP CONSTRAINT IF EXISTS pk_mapping_entries;
ALTER TABLE mapping_entries ADD CONSTRAINT pk_mapping_entries PRIMARY KEY (
    mapping_id, source_catalog_id, guideline_id, target_catalog_id, control_id
);

-- Step 7: Drop policy_id from mapping_entries after backfill and PK change.
ALTER TABLE mapping_entries DROP COLUMN IF EXISTS policy_id;
DROP INDEX IF EXISTS idx_mapping_entries_policy_framework;
CREATE INDEX IF NOT EXISTS idx_mapping_entries_source_target ON mapping_entries(
    source_catalog_id, target_catalog_id, control_id
);
CREATE INDEX IF NOT EXISTS idx_mapping_entries_source_guideline ON mapping_entries(
    source_catalog_id, guideline_id
);
