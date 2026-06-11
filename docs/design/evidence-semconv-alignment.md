# Evidence Semantic Convention Alignment

**Interface contract** between `complytime-collector-components` (exporter config), `complyctl`/ProofWatch (attribute emission), and `complytime-core` (table DDL and query APIs).

Mapping between the `beacon.evidence` OTel semantic convention ([complytime-collector-components/model](https://github.com/complytime/complytime-collector-components/tree/main/model)) and the Studio `evidence` table. PostgreSQL is the primary store; ClickHouse is optional via `pg_clickhouse` FDW (see `docs/decisions/postgres-with-extensions.md`). See [OTel-Native Ingestion](../decisions/otel-native-ingestion.md).

## OTel Collector / exporter alignment

Studio does **not** ship OpenTelemetry Collector configuration. Each environment wires the exporter (see [complytime-collector-components](https://github.com/complytime/complytime-collector-components)) so **log attribute names match this document** and **column names match the Studio DDL** (`internal/postgres/migrations/` and Helm schema init).

| OTel attribute (canonical) | DB column |
|:---------------------------|:----------|
| `compliance.source.registry` | `source_registry` |

If the exporter uses a transform or field rename, apply it so the stored column remains `source_registry` (`Nullable(String)`). This file is the source of truth for the attribute name.

## Attribute-to-Column Mapping

Types below use logical / OTel-aligned naming (e.g. `Enum8`, `DateTime64(3)`, `Nullable(String)`). Concrete PostgreSQL DDL types (`TEXT`, `TIMESTAMPTZ`, `TEXT[]`, etc.) live in `internal/postgres/migrations/`. When ClickHouse FDW is enabled, the exporter maps these to native ClickHouse types.

### Policy Engine Attributes (`registry.policy`)

| Semconv Attribute | DB Column | Type | Requirement |
|:------------------|:------------------|:-----|:------------|
| `policy.engine.name` | `engine_name` | Nullable(String) | recommended |
| `policy.engine.version` | `engine_version` | Nullable(String) | recommended |
| `policy.rule.id` | `rule_id` | String | required |
| `policy.rule.name` | `rule_name` | Nullable(String) | opt_in |
| `policy.rule.uri` | `rule_uri` | Nullable(String) | recommended |
| `policy.evaluation.result` | `eval_result` | Enum8 | required |
| `policy.evaluation.message` | `eval_message` | Nullable(String) | opt_in |
| `policy.target.id` | `target_id` | String | recommended |
| `policy.target.name` | `target_name` | Nullable(String) | recommended |
| `policy.target.type` | `target_type` | Nullable(String) | recommended |
| `policy.target.environment` | `target_env` | Nullable(String) | recommended |

### Compliance Assessment Attributes (`registry.compliance`)

| Semconv Attribute | DB Column | Type | Requirement |
|:------------------|:------------------|:-----|:------------|
| `compliance.control.id` | `control_id` | String DEFAULT '' | required |
| `compliance.control.category` | `control_category` | Nullable(String) | recommended |
| `compliance.control.catalog.id` | `control_catalog_id` | Nullable(String) | required |
| `compliance.control.applicability` | `control_applicability` | Array(String) | opt_in |
| `compliance.frameworks` | `frameworks` | Array(String) | recommended |
| `compliance.requirements` | `requirements` | Array(String) | recommended |
| `compliance.status` | `compliance_status` | Enum8 | required |
| `compliance.risk.level` | `risk_level` | Nullable(Enum8) | opt_in |
| `compliance.remediation.action` | `remediation_action` | Nullable(Enum8) | opt_in |
| `compliance.remediation.status` | `remediation_status` | Nullable(Enum8) | opt_in |
| `compliance.remediation.description` | `remediation_desc` | Nullable(String) | opt_in |
| `compliance.remediation.exception.id` | `exception_id` | Nullable(String) | opt_in |
| `compliance.remediation.exception.active` | `exception_active` | Nullable(Bool) | opt_in |
| `compliance.assessment.id` | `evidence_id` | String | recommended |
### Attestation Provenance (`registry.compliance`)

| Semconv Attribute | DB Column | Type | Requirement |
|:------------------|:------------------|:-----|:------------|
| `compliance.attestation.ref` | `attestation_ref` | Nullable(String) | opt_in |
| `compliance.source.registry` | `source_registry` | Nullable(String) | opt_in |
| `compliance.blob.ref` | `blob_ref` | Nullable(String) | opt_in |

The `attestation_ref` column stores the OCI digest (e.g., `sha256:abc123`) of an in-toto attestation bundle linked to this evidence row. NULL when no attestation is available.

The `source_registry` column stores the OCI registry hostname or URL where the attestation bundle resides. Used for cross-boundary attestation verification when evidence originates from a trust boundary with its own registry. NULL when the default registry applies or provenance is unknown.

The `blob_ref` column stores an S3-compatible URI (e.g., `s3://bucket/key`) pointing to a file artifact (screenshot, log, PDF) associated with this evidence row. NULL for evidence without file attachments. File storage is S3-compatible; the gateway uploads and returns the canonical reference.

### Identity / Timestamps

| Source | DB Column | Type |
|:-------|:------------------|:-----|
| OTel LogRecord timestamp | `collected_at` | DateTime64(3) |
| Insert time | `ingested_at` | DateTime64(3) DEFAULT now64(3) |
| Materialized | `row_key` | concat(evidence_id, '/', control_id, '/', requirement_id) |

## Proposed Semconv Additions

The current `beacon.evidence` entity is missing attributes required for Gemara audit-grade evidence. These extend the `registry.compliance` group without creating a separate namespace.

| Proposed Attribute | Type | DB Column | Rationale |
|:-------------------|:-----|:------------------|:----------|
| `compliance.policy.id` | string | `policy_id` (String DEFAULT '') | Links evidence to the Gemara L3 Policy driving the assessment. Required for the assistant to scope audit queries (`WHERE policy_id = ?`). |
| `compliance.assessment.requirement.id` | string | `requirement_id` (String DEFAULT '') | Assessment granularity below the control level. Gemara EvaluationLogs produce one AssessmentLog per requirement — this is the atomic unit the AuditLog maps to. |
| `compliance.assessment.plan.id` | string | `plan_id` | Ties an assessment to a specific plan within the Policy's `adherence.assessment-plans[]`. Required for cadence validation (did assessments occur at the expected frequency?). |
| `compliance.assessment.confidence` | enum (Undetermined, Low, Medium, High) | `confidence` | Confidence level of the assessment result. Used by the assistant to classify evidence strength and by cross-framework coverage analysis via MappingDocument strength scores. |
| `compliance.assessment.steps` | int | `steps_executed` | Number of evaluation steps executed during the assessment. Provides assessment depth context — a single-step check vs. a multi-step validation suite. |

### Populated By

| Attribute | Populated By |
|:----------|:-------------|
| `compliance.policy.id` | Emitted by ProofWatch (complyctl knows the policy) |
| `compliance.assessment.requirement.id` | Emitted by ProofWatch (complyctl evaluates per requirement) |
| `compliance.assessment.plan.id` | Emitted by ProofWatch (complyctl drives assessment plans) |
| `compliance.assessment.confidence` | Emitted by ProofWatch |
| `compliance.assessment.steps` | Emitted by ProofWatch |
