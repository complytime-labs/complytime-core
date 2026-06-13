-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE target_trusted_publishers
  ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS removed_by_log_index BIGINT;
