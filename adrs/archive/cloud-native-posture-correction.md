# Cloud-Native Posture Correction

**Date**: 2026-04-24
**Status**: Proposed
**Supersedes**: Partial non-goals in [evidence-attestation-pipeline design](../../openspec/changes/evidence-attestation-pipeline/design.md), [audit-dashboard-pivot](audit-dashboard-pivot.md), [agent-interaction-model](agent-interaction-model.md), [authorization-model](authorization-model.md)

## Decision

Rewrite Studio's architectural non-goals to reflect actual user constraints instead of aesthetic preferences. Studio is cloud-native in packaging (Helm, kagent, OCI) but actively resists cloud-native application architecture in four areas that block solving stated user problems.

## Context

Studio's users are compliance analysts and auditors who:

- Assemble evidence from disparate sources (spreadsheets, ticket systems, platforms)
- Cannot pull from trust boundaries — evidence must be pushed out
- Cannot move certain data out of region
- Operate across potentially dozens of trust boundaries and regions
- Need glanceable dashboards, requirement matrices, and exportable reports

Four current design positions actively block these requirements.

## Posture Changes

### 1. "Agent replaces dashboards" → Agent augments dashboards

**Current position** (evidence-attestation-pipeline design, non-goals): "Dashboards — the agent replaces dashboards with natural language queries."

**Problem**: Analysts need glanceable, bookmarkable, exportable views. A compliance matrix showing requirement coverage across a framework is a grid, not a conversation. Auditors hand Excel workbooks and PDFs to clients — chat transcripts are not deliverables.

**New position**: The workbench provides structured views (requirement matrix, evidence browser, posture heatmap) with export capability. The agent supplements these views with synthesis, gap analysis, and natural language queries over the same data. Dashboard and agent share the same ClickHouse query surface.

**What changes**:

| Before | After |
|:--|:--|
| PostureView shows agent-produced summary cards | PostureView shows live ClickHouse aggregates with drill-down |
| No requirement-level grid | Requirement matrix view: Framework → Control → Requirement → Evidence status |
| No export | CSV/Excel/PDF export from any grid view |
| Agent is the primary analyst interface | Agent is a power tool accessible from any view |

### 2. "No distributed orchestration" → Event-driven ingestion is the natural model

**Current position** (evidence-attestation-pipeline design, non-goals): "Distributed orchestration (NATS, message queues)."

**Problem**: Evidence is pushed. That's an event. Decision 12 already bolts async behavior onto the synchronous REST handler ("fire-and-forget posture-check trigger" with deduplication windows). Resisting event-driven patterns while implementing them ad-hoc creates inconsistency.

**New position**: Evidence ingestion emits events. Downstream processing (requirement linking, posture-check triggering, gap notification) subscribes to those events. This does not require NATS or an external message broker — Go channels, a lightweight in-process bus, or ClickHouse's built-in materialized view triggers can serve at current scale. The architectural commitment is to the pattern, not to a specific broker.

**What changes**:

| Before | After |
|:--|:--|
| REST handler synchronously inserts + ad-hoc fires posture-check | REST handler inserts, emits event; subscribers handle downstream |
| Posture-check deduplication is handler-level code | Deduplication is a subscriber concern |
| New processing steps require modifying the handler | New processing steps register as subscribers |

### 3. Data sovereignty via summary-only ingestion

**Current position**: Sovereignty is unmodeled. No mechanism prevents PII-bearing evidence from entering Studio. No concept of where raw evidence resides.

**Problem**: Compliance evidence (screenshots, logs, scan output) often contains PII or regulated data subject to GDPR, EUCS, or other residency requirements. This data cannot leave its trust boundary. Analysts still need a central view of compliance posture across all boundaries.

**New position**: Studio is deployed centrally and receives **summaries only** — pass/fail, control ID, requirement ID, timestamps, metadata. Raw evidence never enters Studio. It stays in a per-boundary OCI registry as attestation bundles, content-addressed and signed. Studio stores a `source_registry` reference so auditors know where to retrieve raw evidence when needed.

```
Trust Boundary                         Central Studio
┌──────────────────────────┐           ┌──────────────────────┐
│                          │           │                      │
│  complyctl scans         │  push     │  ClickHouse          │
│  ↓                       │ ───────►  │  (summaries +        │
│  Raw evidence → OCI      │ summary   │   OCI references)    │
│  registry (attestation   │ + ref     │                      │
│  bundles, never leaves)  │           │  Workbench / Agent   │
│                          │           │                      │
└──────────────────────────┘           └──────────────────────┘
```

**Data flow**:
1. complyctl runs inside the trust boundary, produces evidence
2. Raw artifacts are packaged as in-toto attestation bundles and stored in the boundary's OCI registry
3. complyctl pushes a summary row to Studio (via OTel or REST) containing the OCI digest (`attestation_ref`) and registry hostname (`source_registry`)
4. Studio stores the summary. Raw evidence never crosses the boundary.
5. When an auditor needs the raw artifact, they follow the `source_registry` + `attestation_ref` to the regional registry, subject to that registry's access controls.

**What changes**:

| Before | After |
|:--|:--|
| Sovereignty is unmodeled | Sovereignty is enforced by architecture: summaries in, raw data stays out |
| No `source_registry` field | `source_registry` column on `evidence` table (nullable, populated by complyctl) |
| No guidance on what crosses a boundary | Documented: only summary metadata and OCI digests cross boundaries |
| RACI scopes by policy only | RACI scopes access within Studio; OCI registry auth scopes access to raw evidence |

**What this does NOT require**:
- No `region_id` or `tenant_id` columns — the OCI reference encodes provenance
- No federation layer — Studio is the single central instance
- No regional ClickHouse shards — summaries are small and non-sensitive
- No per-region Studio deployments

### 4. Manual evidence ingest is first-class, not a seed utility

**Current position**: REST/CSV upload exists but populates a thin subset of columns compared to the OTel path. `POST /api/evidence` uses `EvidenceRecord` with 7 fields; the full `evidence` table has 30+ columns.

**Problem**: Analysts upload spreadsheets and attach screenshots. That's the primary evidence path for teams not running OTel collectors. Treating it as a bootstrap utility means manually-ingested evidence lacks requirement linkage, plan association, and assessment metadata — making it invisible to posture checks and audit workflows.

**New position**: REST/CSV/file upload populates the same columns as OTel ingest. Upload handlers accept `requirement_id`, `plan_id`, and assessment fields. File evidence (screenshots, PDFs, logs) is stored in S3-compatible blob storage with a metadata pointer in ClickHouse. Both paths produce the same downstream events.

**What changes**:

| Before | After |
|:--|:--|
| `InsertEvidence` writes 7 columns | `InsertEvidence` writes all semconv-aligned columns |
| No blob storage | S3-compatible store for file evidence; `evidence.blob_ref` column |
| CSV upload is a thin passthrough | CSV upload includes column mapping and validation |
| OTel is the "real" path | Both paths are equally complete |

## Non-Goals That Remain Valid

These non-goals are constraints, not aesthetic preferences. They stay.

| Non-Goal | Why it's still valid                                                                                                              |
|:--|:----------------------------------------------------------------------------------------------------------------------------------|
| Studio does not author artifacts | Engineers use gemara-mcp. Studio consumes.                                                                                        |
| No graph database | ClickHouse JOINs suffice at current entity count. Revisit if relationship queries become the bottleneck.                          |
| No background monitoring (autonomous agent runs) | HITL chatbot model is correct for current trust level. Event-driven processing is infrastructure, not autonomous agent operation. |
| Single gateway binary | Modulith is appropriate at current scale. Extraction seams are preserved.                                                         |
| ClickHouse is the sole query engine | Adding a second database adds operational burden without clear benefit. Schema changes solve the data model gaps.                 |

## Decisions Affected

| Decision | Change |
|:--|:--|
| [Audit Dashboard Pivot](audit-dashboard-pivot.md) | "Dashboard views" row is now the primary UX, not a complement to the chat overlay. Add requirement matrix, export, and structured views. |
| [Agent Interaction Model](agent-interaction-model.md) | Agent remains HITL. "Replaces dashboards" language removed. Agent augments structured views. |
| [Authorization Model](authorization-model.md) | RACI scoping unchanged. Sovereignty handled by summary-only ingestion + OCI references, not schema dimensions. |
| [Backend Architecture](backend-architecture.md) | Event-driven internal bus added as an architectural pattern. Gateway remains a single binary. |
| [Evidence-attestation-pipeline design](../../openspec/changes/evidence-attestation-pipeline/design.md) | Non-goals section updated: "Dashboards" removed, "Distributed orchestration" narrowed to "No external message broker at current scale." |

## Risks

| Risk | Mitigation |
|:--|:--|
| Scope expansion delays shipping | Changes are schema and UX additions, not rewrites. Gateway, agent, ClickHouse, Helm all stay. |
| Sovereignty relies on complyctl discipline | If complyctl pushes raw evidence instead of summaries, Studio has no enforcement. Mitigated by documenting the boundary contract and validating that evidence rows do not contain blob payloads. |
| `source_registry` adds a new column | Nullable, optional, zero impact on existing data. complyctl populates it; manual uploads leave it NULL. |
| Event bus adds internal complexity | In-process Go channels or ClickHouse MV triggers, not an external broker. Complexity is bounded. |
| Manual ingest column mapping requires UI work | Column mapping UI can start as a documented CSV format. Wizard is Phase 2. |
