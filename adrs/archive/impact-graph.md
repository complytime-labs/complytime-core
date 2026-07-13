# Impact Graph: Control Failure Blast Radius

**Status:** Exploratory
**Date:** 2026-04-21

## Context

When a control fails (e.g., BP-4 on `complytime-core`), the immediate question is: "What certifications or ATOs are potentially affected?" The data to answer this already exists across Studio's ClickHouse tables:

| Table | Provides |
|:--|:--|
| `evidence` | Which controls failed, on which targets, when |
| `policies` | Which criteria contain those controls, what assessment requirements exist |
| `mapping_documents` | Which framework objectives (SOC 2 CC8.1, ISO 27001 A.8.9) those controls satisfy |

No one queries these together today. The assistant answers ad hoc questions, but there is no structured traversal that returns a complete impact set. Mapping relationships are trapped inside YAML blobs — no SQL join path exists.

## Problem

A single failed control can affect multiple framework objectives, multiple policies, and multiple targets. Without a traversal, users must manually cross-reference policies, mappings, and evidence to understand scope. This is exactly the manual work Studio exists to eliminate.

## Decision

**Query-time resolution via structured mapping storage + Effective Policy MCP tool.**

Two seams, two concerns:

| Concern | Mechanism | Owner |
|:--|:--|:--|
| Impact / blast radius | SQL join: `evidence × mapping_entries` | Studio (gateway + ClickHouse) |
| Audit preparation (resolved policy) | `effective_policy` MCP tool | Gemara MCP server |

No graph database. The relationships are hierarchical (evidence → control → framework), not arbitrary. Joins handle this.

### Structured Mapping Storage (`mapping_entries`)

Parse mapping YAML at import time into a queryable table. The raw `mapping_documents.content` blob is kept for display; the structured rows enable SQL joins.

```
mapping_entries (new table, populated at import time)
├── mapping_id       ← parent mapping_documents row
├── policy_id        ← mappings[].source context
├── control_id       ← mappings[].source.control-id
├── requirement_id   ← mappings[].source.requirement-id
├── framework        ← top-level framework field
├── reference        ← targets[].reference (e.g., CC8.1)
├── strength         ← targets[].strength
├── confidence       ← targets[].confidence-level
└── imported_at      ← auto
```

Impact query becomes pure SQL:

```sql
SELECT e.control_id, e.target_name, e.eval_result,
       m.framework, m.reference, m.strength, m.confidence
FROM evidence e
JOIN mapping_entries m
  ON e.policy_id = m.policy_id AND e.control_id = m.control_id
WHERE e.policy_id = 'ampel-branch-protection'
  AND e.eval_result IN ('Failed', 'Not Run')
  AND e.collected_at >= '2026-04-16'
ORDER BY m.framework, m.reference, m.strength DESC
```

No YAML parsing at query time. No MCP tool needed. The assistant uses `run_select_query` with a pattern from the evidence-schema skill.

### Effective Policy MCP Tool (upstream dependency)

To produce an AuditLog (L7), the assistant needs a fully resolved policy: criteria with control catalog references inlined, assessment requirements expanded, mappings attached. This "Effective Policy" is a Gemara-schema-aware computation.

**Upstream dependency:** [gemaraproj/go-gemara#64](https://github.com/gemaraproj/go-gemara/issues/64) — "Create Gemara bundle resolution logic for consumers." Adds `Effective Catalog` and `Effective Policy` types that resolve `imports` and `extends` statements via OCI URIs.

Once `go-gemara` ships this:

1. Gemara MCP server wraps it as an `effective_policy` tool.
2. Assistant calls `effective_policy(policy_id)` during audit preparation.
3. Returns a single resolved document with all references inlined.

**These two workstreams are independent.** The blast radius (mapping_entries) has no dependency on go-gemara#64. The Effective Policy tool arrives when the upstream library is ready.

```
go-gemara #64                     Studio (this repo)
═══════════════                   ══════════════════

Effective Catalog ──┐
                    ├──▶ gemara-mcp ──▶ effective_policy tool
Effective Policy ───┘                  (blocked on #64)


                    MEANWHILE (no dependency)

                    mapping_entries table
                    + import-time YAML parsing
                    + impact query pattern in skill
                    = blast radius works now
```

## Rejected Approaches

| Approach | Why Not |
|:--|:--|
| RDF / knowledge graph | Adds infrastructure for relationship types Gemara already models as typed artifacts. |
| Dedicated `blast_radius` MCP tool | The join is simple enough that a SQL query pattern in the assistant skill handles it. No custom tool needed. |
| Materialized view (pre-join on insert) | Requires parsing Gemara YAML inside ClickHouse. Couples the schema engine to the storage engine. |
| Emitter-side population (complyctl populates `frameworks` column) | Couples the scanner to the mapping. Adding a new mapping after scan time wouldn't update old evidence. Studio owns mapping resolution. |
| `policy_criteria` structured table | Not needed for impact. The assistant reads policy YAML fine for display. Effective Policy MCP tool handles the resolved view for audit. |
| Drift detection | Comparing evidence across dates is a Grafana dashboard over ClickHouse. Not a Studio feature. |

## Implementation Steps

| Step | What | Dependency |
|:--|:--|:--|
| 1 | `mapping_entries` ClickHouse table + schema migration | None |
| 2 | Parse mapping YAML at import time, write structured rows | Step 1 |
| 3 | Impact query pattern added to `skills/evidence-schema/SKILL.md` | Step 2 |
| 4 | `effective_policy` MCP tool in gemara-mcp | go-gemara#64 |

## Open Questions

- Should the impact query also return passing controls for context ("5/7 controls pass for CC8.1")?
- Should the `frameworks` and `requirements` Array columns on `evidence` be backfilled from `mapping_entries` as a cache, or left empty?
- Does the UI need a dedicated impact view, or is the assistant response sufficient for now?
- Should `mapping_entries` be populated retroactively for existing mapping documents on schema migration?

## Related

- [OTel-Native Ingestion](otel-native-ingestion.md) — evidence pipeline
- [Procedure Compliance: BPMN and Gemara](procedure-compliance-coverage.md) — Gemara layer coverage
- [Evidence Integrity Chain](evidence-integrity-chain.md) — trust model for evidence data
- `skills/evidence-schema/SKILL.md` — ClickHouse table schemas
- [gemaraproj/go-gemara#64](https://github.com/gemaraproj/go-gemara/issues/64) — upstream bundle resolution
