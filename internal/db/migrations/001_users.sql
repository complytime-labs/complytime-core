-- SPDX-License-Identifier: Apache-2.0
-- Migration 001: users and role_changes tables

CREATE TABLE IF NOT EXISTS users (
    sub         TEXT NOT NULL DEFAULT '',
    issuer      TEXT NOT NULL DEFAULT '',
    email       TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    avatar_url  TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'reviewer',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sub_issuer ON users(sub, issuer) WHERE sub != '';

CREATE TABLE IF NOT EXISTS role_changes (
    id           BIGSERIAL PRIMARY KEY,
    changed_by   TEXT NOT NULL,
    target_email TEXT NOT NULL,
    old_role     TEXT NOT NULL,
    new_role     TEXT NOT NULL,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_role_changes_target ON role_changes(target_email);
