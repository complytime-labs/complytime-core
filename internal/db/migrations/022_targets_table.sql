-- SPDX-License-Identifier: Apache-2.0
-- Migration 022: Create targets table for publisher-registered target dimensions

CREATE TABLE IF NOT EXISTS targets (
    target_id           TEXT NOT NULL,
    tessera_log_index   BIGINT NOT NULL,
    target_name         TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    technologies        TEXT[] NOT NULL DEFAULT '{}',
    geopolitical        TEXT[] NOT NULL DEFAULT '{}',
    sensitivity         TEXT[] NOT NULL DEFAULT '{}',
    users               TEXT[] NOT NULL DEFAULT '{}',
    groups              TEXT[] NOT NULL DEFAULT '{}',
    registered_at       TIMESTAMPTZ NOT NULL,
    registered_by       TEXT NOT NULL,

    PRIMARY KEY (target_id, tessera_log_index)
);

CREATE INDEX IF NOT EXISTS idx_targets_registered_at ON targets(target_id, registered_at DESC);

COMMENT ON TABLE targets IS 'Append-only target registrations with dimensional metadata for policy matching';
COMMENT ON COLUMN targets.registered_by IS 'JWT sub claim of the publisher who registered this target';
