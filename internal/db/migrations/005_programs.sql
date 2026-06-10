-- SPDX-License-Identifier: Apache-2.0
-- Migration 005: programs, jobs, and guidance_entries applicability

CREATE TABLE IF NOT EXISTS programs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    guidance_catalog_id TEXT REFERENCES catalogs(catalog_id),
    framework           TEXT NOT NULL,
    applicability       TEXT[] NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'intake',
    health              TEXT,
    owner               TEXT,
    description         TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}',
    policy_ids          TEXT[] NOT NULL DEFAULT '{}',
    environments        TEXT[] NOT NULL DEFAULT '{}',
    version             INTEGER NOT NULL DEFAULT 1,
    green_pct           INT NOT NULL DEFAULT 90,
    red_pct             INT NOT NULL DEFAULT 50,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT programs_status_check CHECK (status IN ('intake', 'active', 'monitoring', 'renewal', 'closed')),
    CONSTRAINT programs_threshold_check CHECK (red_pct < green_pct)
);
CREATE INDEX IF NOT EXISTS idx_programs_status ON programs(status) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id  UUID NOT NULL REFERENCES programs(id),
    agent       TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_jobs_program ON jobs(program_id, created_at DESC);

-- Add applicability column to guidance_entries for baseline filtering
ALTER TABLE guidance_entries ADD COLUMN IF NOT EXISTS applicability TEXT[] NOT NULL DEFAULT '{}';
