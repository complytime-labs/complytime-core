-- SPDX-License-Identifier: Apache-2.0
-- Migration 009: Program members — links users to programs with roles and
-- control ownership areas. Replaces single-owner model with a roster.

CREATE TABLE IF NOT EXISTS program_members (
    program_id  UUID NOT NULL REFERENCES programs(id),
    user_email  TEXT NOT NULL REFERENCES users(email),
    role        TEXT NOT NULL DEFAULT 'contributor',
    owns        TEXT[] NOT NULL DEFAULT '{}',
    notes       TEXT,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (program_id, user_email),
    CONSTRAINT program_members_role_check CHECK (
        role IN ('owner', 'manager', 'contributor', 'viewer')
    )
);
CREATE INDEX IF NOT EXISTS idx_program_members_email ON program_members(user_email);
