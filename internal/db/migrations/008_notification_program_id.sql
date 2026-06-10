-- SPDX-License-Identifier: Apache-2.0
-- Migration 008: Fix notification policy_id overloading for program health changes.
-- Adds program_id and severity columns so program-level notifications stop
-- abusing policy_id to store severity strings.

ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS program_id TEXT,
    ADD COLUMN IF NOT EXISTS severity TEXT;

CREATE INDEX IF NOT EXISTS idx_notifications_program ON notifications(program_id)
    WHERE program_id IS NOT NULL;
