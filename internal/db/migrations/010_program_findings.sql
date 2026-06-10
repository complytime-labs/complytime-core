-- SPDX-License-Identifier: Apache-2.0
-- Migration 010: Program findings — persistent action items extracted from
-- promoted AuditLogs and posture checks. Bridges assistant-surfaced gaps
-- to tracked remediation items.

CREATE TABLE IF NOT EXISTS program_findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id  UUID NOT NULL REFERENCES programs(id),
    policy_id   TEXT NOT NULL,
    source      TEXT NOT NULL,
    source_id   TEXT,
    type        TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    owner       TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    severity    TEXT,
    target_date DATE,
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT program_findings_status_check CHECK (
        status IN ('open', 'in_progress', 'resolved', 'accepted', 'deferred')
    ),
    CONSTRAINT program_findings_type_check CHECK (
        type IN ('Finding', 'Gap', 'Observation', 'Risk')
    ),
    CONSTRAINT program_findings_source_check CHECK (
        source IN ('audit_log', 'posture_check', 'manual')
    )
);
CREATE INDEX IF NOT EXISTS idx_program_findings_program ON program_findings(program_id, status);
CREATE INDEX IF NOT EXISTS idx_program_findings_policy ON program_findings(policy_id);
CREATE INDEX IF NOT EXISTS idx_program_findings_source ON program_findings(source_id)
    WHERE source_id IS NOT NULL;
