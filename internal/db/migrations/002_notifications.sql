-- SPDX-License-Identifier: Apache-2.0
-- Migration 002: notifications table

CREATE TABLE IF NOT EXISTS notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id TEXT NOT NULL,
    type            TEXT NOT NULL,
    policy_id       TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    read            BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read, created_at DESC) WHERE NOT read;
