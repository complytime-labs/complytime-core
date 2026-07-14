# Enforcement Log Traceability

**Date**: 2026-04-24
**Status**: Exploratory

## Decision

Studio must ingest EnforcementLogs and maintain the traceability chain from enforcement actions back to the EvaluationLog findings that triggered them. This linkage is mandatory at audit time.

## Context

complyctl produces EvaluationLogs (L5) containing assessment findings. Non-compliance findings trigger enforcement actions — either preventive (Gate: block before deployment) or remediative (Remediation: fix after detection). These enforcement actions are recorded as Gemara `#EnforcementLog` artifacts (L6).

Auditors must answer: "What finding triggered this enforcement action, and what evaluation produced that finding?" Today, Studio ingests EvaluationLogs as evidence but has no concept of EnforcementLogs. The traceability chain exists in the Gemara schema but Studio does not store, query, or surface it.

## Gemara Schema (existing)

The `#EnforcementLog` already models the full chain:

- `ActionResult.method` → Policy `enforcement-methods[]` (type: Gate or Remediation)
- `ActionResult.justification.assessments[].log` → EvaluationLog entry that produced the finding
- `ActionResult.justification.assessments[].plan` → Policy assessment plan that was executed
- `ActionResult.justification.assessments[].requirement` → L2 assessment requirement that was evaluated
- `ActionResult.justification.exceptions[]` → Policy exceptions that authorized the action

## What Studio Needs

| Concern | Requirement |
|:---|:---|
| Ingest | Accept EnforcementLogs via OTel and REST (same paths as EvaluationLogs) |
| Store | ClickHouse table for enforcement actions preserving the justification chain |
| Link | JOIN enforcement actions to evidence rows via the `log` entry mapping |
| Surface | At audit time, show the full chain: Control → Finding → EvaluationLog → Enforcement Action → Disposition |

## Schema Direction

```
enforcement_actions
├── action_id
├── policy_id
├── enforcement_method_id    → Policy adherence.enforcement-methods[].id
├── enforcement_type         → Gate | Remediation
├── disposition              → Enforced | Tolerated | Clear
├── source_evaluation_id     → evidence.evidence_id (the EvaluationLog entry)
├── requirement_id           → L2 assessment requirement
├── plan_id                  → Policy assessment plan
├── exception_refs           → Array(String), policy exception references
├── message
├── started_at
├── ended_at
├── source_registry          → OCI registry where the full EnforcementLog bundle resides
├── attestation_ref          → OCI digest of the EnforcementLog artifact
├── ingested_at
```

The `source_evaluation_id` → `evidence.evidence_id` JOIN is the critical link. It answers "which EvaluationLog finding caused this enforcement action."

## Not Decided Yet

- Whether the posture-check skill should incorporate enforcement status (e.g., "Finding exists but enforcement action resolved it")
- Whether the AuditLog template should include enforcement action references in results
- Whether enforcement dispositions affect the 7-state classification (a "Failing" evidence row with a successful remediation enforcement may no longer be "Failing")
- ClickHouse table engine and partitioning strategy

## Related

- [Cloud-Native Posture Correction](cloud-native-posture-correction.md) — sovereignty model applies equally to EnforcementLogs (summaries in Studio, raw artifacts in regional OCI)
- [Evidence-Attestation Pipeline](../../openspec/changes/evidence-attestation-pipeline/design.md) — same ingest pattern, same attestation model
