# Procedure Compliance: BPMN and Gemara Coverage

**Status:** Exploratory
**Date:** 2026-04-21

## Context

NIST 800-53 "-1" controls (AC-1, AT-1, AU-1, etc.) require organizations to define, document, and follow procedures for implementing each control family. A "modeled approach" uses formal process modeling (BPMN) with an execution engine to make procedures executable and self-documenting. The execution log becomes the evidence.

This explores where Gemara's layer model covers the "-1" pattern and where gaps remain.

## Mapping

| "-1" Requirement            | BPMN Approach              | Gemara Approach                                      |
|:----------------------------|:---------------------------|:-----------------------------------------------------|
| Procedure documented        | Executable process model   | GuidanceCatalog (L1)                                 |
| Control objectives defined  | Decision gates in the flow | ControlCatalog (L2) with assessment requirements     |
| Review schedule established | Timer events, escalations  | Policy.adherence (L3) with assessment plan frequency |
| Evidence of implementation  | Process execution log      | EvaluationLog (L5) tied to specific requirements     |
| Enforcement on failure      | Error handling branches    | EnforcementLog (L6) with remediation actions         |
| Audit opinion               | N/A (separate system)      | AuditLog (L7) with per-criteria classification       |

## Two Approaches

BPMN proves compliance through **execution** — the process ran, therefore the procedure was followed. Gemara proves compliance through **evidence** — assessments were performed, findings were recorded, the audit result is classified.

These are complementary, not competing. An organization could model procedures in BPMN and feed execution logs into Gemara's evidence pipeline. The question is whether the added infrastructure (JVM runtime, process engine, model authoring tooling) is justified when most organizations already have task orchestration.

## What Gemara Covers

- The "-1" pattern is largely served by existing layers: L1 (guidance), L2 (controls), L3 (policy + adherence plans), L5/L6 (evidence), L7 (audit).
- GuidanceCatalog (L1) is the natural home for procedure documentation.
- Policy.adherence (L3) models review schedules and assessment cadence.
- Evidence pipeline (L5/L6) captures proof that procedures were followed.

## What Gemara Doesn't Cover

- **Executable process enforcement** — Gemara detects non-compliance after the fact rather than preventing a procedure from being skipped.
- **Process modeling** — No formal notation for describing procedure flows. GuidanceCatalog is prose/structured text.
- **Automated escalation** — No timers, SLA enforcement, or routing logic.

Many organizations already address these with tools like Jira, GitHub Projects, ServiceNow, or Linear — scheduled triggers, assignment routing, approval gates, SLA timers, and execution logs. A dedicated BPMN engine may duplicate what these tools provide, though that depends on the organization's maturity and complexity.

The potentially interesting gap is the **evidence bridge**: getting completion events from existing task management tools into Studio as L5 EvaluationLog evidence via the OTel pipeline.

## Open Questions

- Can completion events from tools like Jira (issue closed, approval logged) flow through OTel as EvaluationLog evidence?
- Should GuidanceCatalog support structured procedure descriptions (steps, decision points, roles) beyond free-form text?
- Is evidence-based proof sufficient for "-1" controls, or will auditors eventually want executable process guarantees?
