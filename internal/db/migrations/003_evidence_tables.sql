-- SPDX-License-Identifier: Apache-2.0
-- Migration 003: evidence and analytics tables

-- Natural grain: one row per (evidence_id, control_id, requirement_id).
CREATE TABLE IF NOT EXISTS policies (
    policy_id     TEXT PRIMARY KEY,
    title         TEXT NOT NULL DEFAULT '',
    version       TEXT,
    oci_reference TEXT NOT NULL DEFAULT '',
    content       TEXT NOT NULL DEFAULT '',
    imported_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    imported_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_policies_imported_at ON policies(imported_at DESC);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id            TEXT NOT NULL,
    target_id              TEXT NOT NULL,
    target_name            TEXT,
    target_type            TEXT,
    target_env             TEXT,
    engine_name            TEXT,
    engine_version         TEXT,
    rule_id                TEXT NOT NULL DEFAULT '',
    rule_name              TEXT,
    rule_uri               TEXT,
    eval_result            TEXT NOT NULL,
    eval_message           TEXT,
    policy_id              TEXT NOT NULL DEFAULT '',
    control_id             TEXT NOT NULL DEFAULT '',
    control_catalog_id     TEXT,
    control_category       TEXT,
    control_applicability  TEXT[] NOT NULL DEFAULT '{}',
    requirement_id         TEXT NOT NULL DEFAULT '',
    plan_id                TEXT,
    confidence             TEXT,
    steps_executed         INTEGER,
    compliance_status      TEXT NOT NULL,
    risk_level             TEXT,
    requirements           TEXT[] NOT NULL DEFAULT '{}',
    remediation_action     TEXT,
    remediation_status     TEXT,
    remediation_desc       TEXT,
    exception_id           TEXT,
    exception_active       BOOLEAN,
    enrichment_status      TEXT NOT NULL,
    attestation_ref        TEXT,
    source_registry        TEXT,
    blob_ref               TEXT,
    certified              BOOLEAN NOT NULL DEFAULT false,
    owner                  TEXT,
    collected_at           TIMESTAMPTZ NOT NULL,
    ingested_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_key                TEXT GENERATED ALWAYS AS (
        evidence_id || '/' || control_id || '/' || requirement_id
    ) STORED,
    CONSTRAINT pk_evidence PRIMARY KEY (evidence_id, control_id, requirement_id),
    CONSTRAINT evidence_eval_result_chk CHECK (
        eval_result IN (
            'Not Run', 'Passed', 'Failed', 'Needs Review', 'Not Applicable', 'Unknown'
        )
    ),
    CONSTRAINT evidence_compliance_status_chk CHECK (
        compliance_status IN (
            'Compliant', 'Non-Compliant', 'Exempt', 'Not Applicable', 'Unknown'
        )
    ),
    CONSTRAINT evidence_confidence_chk CHECK (
        confidence IS NULL OR confidence IN (
            'Undetermined', 'Low', 'Medium', 'High'
        )
    ),
    CONSTRAINT evidence_risk_level_chk CHECK (
        risk_level IS NULL OR risk_level IN (
            'Critical', 'High', 'Medium', 'Low', 'Informational'
        )
    ),
    CONSTRAINT evidence_remediation_action_chk CHECK (
        remediation_action IS NULL OR remediation_action IN (
            'Block', 'Allow', 'Remediate', 'Waive', 'Notify', 'Unknown'
        )
    ),
    CONSTRAINT evidence_remediation_status_chk CHECK (
        remediation_status IS NULL OR remediation_status IN (
            'Success', 'Fail', 'Skipped', 'Unknown'
        )
    ),
    CONSTRAINT evidence_enrichment_status_chk CHECK (
        enrichment_status IN (
            'Success', 'Unmapped', 'Partial', 'Unknown', 'Skipped'
        )
    )
);
CREATE INDEX IF NOT EXISTS idx_evidence_target_policy ON evidence(
    target_id, policy_id, control_id, collected_at
);
CREATE INDEX IF NOT EXISTS idx_evidence_policy_collected ON evidence(policy_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_row_key ON evidence(row_key);
CREATE INDEX IF NOT EXISTS idx_evidence_plan ON evidence(plan_id) WHERE plan_id IS NOT NULL AND plan_id != '';
CREATE INDEX IF NOT EXISTS idx_evidence_eval ON evidence(policy_id, eval_result);
CREATE INDEX IF NOT EXISTS idx_evidence_owner ON evidence(owner) WHERE owner IS NOT NULL;

CREATE TABLE IF NOT EXISTS mapping_documents (
    mapping_id  TEXT PRIMARY KEY,
    policy_id   TEXT NOT NULL DEFAULT '',
    framework   TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mapping_documents_policy ON mapping_documents(policy_id);

CREATE TABLE IF NOT EXISTS mapping_entries (
    mapping_id     TEXT NOT NULL,
    policy_id      TEXT NOT NULL DEFAULT '',
    control_id     TEXT NOT NULL DEFAULT '',
    requirement_id TEXT NOT NULL DEFAULT '',
    framework      TEXT NOT NULL DEFAULT '',
    reference      TEXT NOT NULL DEFAULT '',
    strength       INTEGER NOT NULL DEFAULT 0,
    confidence     TEXT NOT NULL DEFAULT '',
    imported_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_mapping_entries PRIMARY KEY (
        mapping_id, policy_id, framework, control_id, reference, requirement_id
    )
);
CREATE INDEX IF NOT EXISTS idx_mapping_entries_policy_framework ON mapping_entries(
    policy_id, framework, control_id
);

CREATE TABLE IF NOT EXISTS catalogs (
    catalog_id   TEXT PRIMARY KEY,
    catalog_type TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL DEFAULT '',
    content      TEXT NOT NULL DEFAULT '',
    policy_id    TEXT NOT NULL DEFAULT '',
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_catalogs_policy ON catalogs(policy_id);

CREATE TABLE IF NOT EXISTS controls (
    catalog_id  TEXT NOT NULL,
    control_id  TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    objective   TEXT NOT NULL DEFAULT '',
    group_id    TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'Active',
    policy_id   TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_controls PRIMARY KEY (catalog_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_controls_policy ON controls(policy_id);

CREATE TABLE IF NOT EXISTS assessment_requirements (
    catalog_id      TEXT NOT NULL,
    control_id      TEXT NOT NULL,
    requirement_id  TEXT NOT NULL,
    text            TEXT NOT NULL DEFAULT '',
    applicability   TEXT[] NOT NULL DEFAULT '{}',
    recommendation  TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'Active',
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_assessment_requirements PRIMARY KEY (
        catalog_id, control_id, requirement_id
    )
);

CREATE TABLE IF NOT EXISTS control_threats (
    catalog_id          TEXT NOT NULL,
    control_id          TEXT NOT NULL,
    threat_reference_id TEXT NOT NULL,
    threat_entry_id     TEXT NOT NULL,
    imported_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_control_threats PRIMARY KEY (
        catalog_id, control_id, threat_reference_id, threat_entry_id
    )
);

CREATE TABLE IF NOT EXISTS threats (
    catalog_id  TEXT NOT NULL,
    threat_id   TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    group_id    TEXT NOT NULL DEFAULT '',
    policy_id   TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_threats PRIMARY KEY (catalog_id, threat_id)
);
CREATE INDEX IF NOT EXISTS idx_threats_policy ON threats(policy_id);

CREATE TABLE IF NOT EXISTS risks (
    catalog_id  TEXT NOT NULL,
    risk_id     TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    group_id    TEXT NOT NULL DEFAULT '',
    impact      TEXT NOT NULL DEFAULT '',
    policy_id   TEXT NOT NULL DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_risks PRIMARY KEY (catalog_id, risk_id)
);
CREATE INDEX IF NOT EXISTS idx_risks_policy ON risks(policy_id);

CREATE TABLE IF NOT EXISTS risk_threats (
    catalog_id          TEXT NOT NULL,
    risk_id             TEXT NOT NULL,
    threat_reference_id TEXT NOT NULL,
    threat_entry_id     TEXT NOT NULL,
    imported_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_risk_threats PRIMARY KEY (
        catalog_id, risk_id, threat_reference_id, threat_entry_id
    )
);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id      TEXT PRIMARY KEY,
    policy_id     TEXT NOT NULL DEFAULT '',
    audit_start   TIMESTAMPTZ NOT NULL,
    audit_end     TIMESTAMPTZ NOT NULL,
    framework     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT,
    content       TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    model         TEXT,
    prompt_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_policy_start ON audit_logs(policy_id, audit_start DESC);

CREATE TABLE IF NOT EXISTS draft_audit_logs (
    draft_id        TEXT PRIMARY KEY,
    policy_id       TEXT NOT NULL DEFAULT '',
    audit_start     TIMESTAMPTZ NOT NULL,
    audit_end       TIMESTAMPTZ NOT NULL,
    framework       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL,
    content         TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL DEFAULT '',
    agent_reasoning TEXT NOT NULL DEFAULT '',
    model           TEXT,
    prompt_version  TEXT,
    reviewed_by     TEXT,
    promoted_at     TIMESTAMPTZ,
    reviewer_edits  TEXT NOT NULL DEFAULT '{}',
    CONSTRAINT draft_audit_logs_status_chk CHECK (
        status IN ('pending_review', 'promoted', 'expired')
    )
);
CREATE INDEX IF NOT EXISTS idx_draft_audit_logs_policy_start ON draft_audit_logs(
    policy_id, audit_start DESC
);
CREATE INDEX IF NOT EXISTS idx_draft_audit_logs_status ON draft_audit_logs(status);

CREATE TABLE IF NOT EXISTS evidence_assessments (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id      TEXT NOT NULL,
    policy_id        TEXT NOT NULL DEFAULT '',
    plan_id          TEXT NOT NULL DEFAULT '',
    classification   TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    assessed_at      TIMESTAMPTZ NOT NULL,
    assessed_by      TEXT NOT NULL DEFAULT '',
    CONSTRAINT evidence_assessments_classification_chk CHECK (
        classification IN (
            'Healthy',
            'Failing',
            'Wrong Source',
            'Wrong Method',
            'Unfit Evidence',
            'Stale',
            'No Evidence'
        )
    )
);
CREATE INDEX IF NOT EXISTS idx_evidence_assessments_policy_plan ON evidence_assessments(
    policy_id, plan_id, evidence_id, assessed_at DESC
);
CREATE INDEX IF NOT EXISTS idx_evidence_assessments_evidence ON evidence_assessments(evidence_id);

CREATE TABLE IF NOT EXISTS certifications (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id       TEXT NOT NULL,
    certifier         TEXT NOT NULL DEFAULT '',
    certifier_version TEXT NOT NULL DEFAULT '',
    result            TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    certified_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT certifications_result_chk CHECK (
        result IN ('pass', 'fail', 'skip', 'error')
    )
);
CREATE INDEX IF NOT EXISTS idx_certifications_evidence_certifier ON certifications(
    evidence_id, certifier, certified_at DESC
);

