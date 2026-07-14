# ADR 0033: Evidence Quality Boundary

**Status:** Accepted
**Date:** 2026-05-15

## Context

Both the data platform and the workbench analyze evidence quality, but at different scopes. Without a clear boundary, logic leaks across services — the platform attempts cumulative analysis it should not own, or the workbench reimplements per-record checks.

## Decision

Split evidence quality into two distinct scopes.

### Data platform certifier (per-record, deterministic, runs on every ingest)

| Certifier | Check | Data needed |
|:---|:---|:---|
| schema | Required fields, valid enums, timestamps not zero/future | Evidence record |
| provenance | Known registry, attestation ref, engine allowlist | Evidence record |
| freshness (basic) | `collected_at` not future, not older than configurable max age | Evidence record |
| freshness (policy-aware) | Evidence current within policy's compliance window | Evidence + policy |
| relevance | Evidence maps to a valid control/requirement in its declared policy | Evidence + policy + requirements |

Policy-aware freshness and relevance are planned additions. Schema, provenance, and executor certifiers exist today.

### Workbench / Agent (cumulative, on-demand)

| Analysis | Scope |
|:---|:---|
| Coverage | All requirements in a policy covered by evidence? |
| Sufficiency | Program thresholds met? |
| Gap detection | Which requirements lack evidence? |
| Consistency | Conflicting results across sources? |
| Program readiness | Timeline, team, workflow status |

### Boundary

The data platform answers: "Is this record trustworthy and applicable?"

The workbench answers: "Do we have enough good evidence to pass?"

## Consequences

- Certifiers remain in `complytime-core` — they run on every ingest via the NATS pipeline.
- Coverage, gap detection, and sufficiency analysis move to `complytime-studio` (workbench).
- The workbench reads certification results from the core via REST/MCP — it does not re-evaluate per-record trust.
- Adding new certifiers (policy freshness, relevance) is a core concern, not a workbench concern.
