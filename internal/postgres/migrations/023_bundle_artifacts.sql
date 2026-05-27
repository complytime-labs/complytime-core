-- SPDX-License-Identifier: Apache-2.0
-- Migration 023: Create bundle_artifacts table for OCI bundle tracking

CREATE TABLE IF NOT EXISTS bundle_artifacts (
    bundle_id           TEXT NOT NULL,
    tessera_log_index   BIGINT NOT NULL,
    artifact_type       TEXT NOT NULL,
    artifact_id         TEXT NOT NULL,
    oci_reference       TEXT,
    imported_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (bundle_id, tessera_log_index)
);

CREATE INDEX IF NOT EXISTS idx_bundle_artifacts_type ON bundle_artifacts(bundle_id, artifact_type);

COMMENT ON TABLE bundle_artifacts IS 'Tracks all artifacts belonging to an OCI bundle import for effective policy resolution';
