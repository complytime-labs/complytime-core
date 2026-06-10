-- SPDX-License-Identifier: Apache-2.0
-- Migration 007: recommendation dismissals per-program

CREATE TABLE IF NOT EXISTS recommendation_dismissals (
    program_id UUID NOT NULL REFERENCES programs(id),
    policy_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (program_id, policy_id)
);
