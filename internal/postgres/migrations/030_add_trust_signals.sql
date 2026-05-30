-- SPDX-License-Identifier: Apache-2.0
-- Migration 030: Add trust_signals table
-- Phase 1: Trust Signals (backward compatible)

CREATE TABLE IF NOT EXISTS trust_signals (
    evidence_id       TEXT NOT NULL,
    layer             TEXT NOT NULL,  -- 'identity', 'quality', 'attestation'
    check_name        TEXT NOT NULL,  -- 'schema', 'provenance', 'executor', 'freshness', 'relevance', 'publisher_auth'
    result            TEXT NOT NULL,  -- 'pass', 'fail', 'skip', 'error'
    reason            TEXT NOT NULL DEFAULT '',
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (evidence_id, layer, check_name),

    CONSTRAINT trust_signals_layer_chk CHECK (
        layer IN ('identity', 'quality', 'attestation')
    ),
    CONSTRAINT trust_signals_result_chk CHECK (
        result IN ('pass', 'fail', 'skip', 'error')
    )
);

CREATE INDEX IF NOT EXISTS idx_trust_signals_result
    ON trust_signals(evidence_id, result);

CREATE INDEX IF NOT EXISTS idx_trust_signals_layer
    ON trust_signals(layer, check_name, result);

COMMENT ON TABLE trust_signals IS
    'Queryable trust signals for each evidence verification check';
COMMENT ON COLUMN trust_signals.layer IS
    'Verification layer: identity (Layer 1), quality (Layer 2), attestation (Layer 3)';
COMMENT ON COLUMN trust_signals.check_name IS
    'Specific check: publisher_auth, schema, provenance, executor, freshness, relevance';
COMMENT ON COLUMN trust_signals.result IS
    'Check result: pass (passed), fail (failed), skip (not applicable), error (check failed to run)';
