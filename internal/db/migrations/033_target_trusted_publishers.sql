-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS target_trusted_publishers (
    target_id         TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    sub_pattern       TEXT NOT NULL,
    environment       TEXT,
    added_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by          TEXT,
    tessera_log_index BIGINT,
    PRIMARY KEY (target_id, issuer, sub_pattern)
);

CREATE INDEX IF NOT EXISTS idx_target_trusted_publishers_target_id
    ON target_trusted_publishers (target_id);
