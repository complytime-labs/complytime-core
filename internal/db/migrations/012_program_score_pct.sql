-- SPDX-License-Identifier: Apache-2.0
-- Migration 012: Add score_pct to programs for actual computed posture score.
-- green_pct/red_pct are thresholds; score_pct is the real pass rate.

ALTER TABLE programs ADD COLUMN IF NOT EXISTS score_pct INT NOT NULL DEFAULT 0;
