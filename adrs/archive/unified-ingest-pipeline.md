# ADR #0034 — Unified Ingest Pipeline

**Status:** Accepted
**Date:** 2026-05-16
**Supersedes:** Partially supersedes #0028 (Async Evidence Ingest) scope

## Context

The gateway historically had multiple overlapping content paths for Gemara artifacts: registry-backed startup pulls, synchronous import handlers, separate evidence ingest routes with optional async duplication, and type detection logic split across import and ingest handlers.

Problems:

1. **Parallel paths:** Catalogs/policies import synchronously in the request handler. Evidence had overlapping sync/async paths before unification. Type detection and storage logic was duplicated across `handlers_import.go` and `ingest_handler.go`.
2. **Hardcoded seed:** Startup-only catalog population used a fixed repo list and handled only two catalog types, duplicating `/api/import`.
3. **Inconsistent async:** Evidence used NATS for async processing earlier; policies and catalogs did not. Async infrastructure existed but only partially covered artifact types.
4. **Deployment complexity:** Docker Compose could require separate containers feeding different code paths to populate the same database.

## Decision

Collapse all content ingestion into a single async pipeline:

```
POST /api/ingest  →  accept raw content  →  assign job ID  →  NATS ingest.artifact  →  worker
```

The worker:
1. Detects artifact type via `metadata.type`
2. Routes to the appropriate storage function (evidence flatten, policy insert, catalog parse, mapping parse)
3. Updates job status tracker
4. Publishes downstream events (e.g., `core.evidence.<policy_id>` for certifier)

### Single Endpoint Contract

```
POST /api/ingest
Content-Type: application/x-yaml | application/json

→ 202 Accepted {"job_id": "<uuid>", "status": "pending"}
```

```
GET /api/ingest/jobs/{job_id}

→ 200 {"job_id": "...", "status": "completed|failed|pending", "result": {...}}
```

### OCI Reference Support

OCI bundle import remains a separate concern — it resolves an OCI reference into individual artifact YAMLs, then feeds each one into the same ingest pipeline. Implemented as a thin wrapper:

```
POST /api/import
{"reference": "registry:5000/org/bundle:tag"}

→ Pulls bundle → publishes each artifact to NATS ingest.artifact → returns job IDs
```

This keeps OCI resolution (network I/O, authentication) at the API boundary while reusing the unified worker for all parsing and storage.

### NATS Subject Consolidation

| Prior subject (legacy namespace) | New |
|---|---|
| Raw ingest lane (formerly evidence-only) | `core.ingest` (all artifact types) |
| Post-insert certifier fan-out | `core.evidence.<policy_id>` |
| Draft audit-log fan-out | `core.draft.<policy_id>` |

The unified ingest lane carries all artifact types. The worker determines the type and routes internally.

### Startup Seed

The gateway no longer pulls catalogs implicitly at startup. Seeding runs as one or more explicit jobs (container or init script) that post artifacts to `POST /api/ingest`, same as any other client. Operators no longer rely on startup registry seed helpers in the gateway binary.

## Consequences

**Positive:**
- One ingestion path for all Gemara content — policies, catalogs, evidence, mappings
- Async by default; consistent job tracking for all artifact types
- Seed is just another API client — no special startup logic
- Docker Compose collapses from two seed containers to one pattern
- Worker is the single place to add new artifact type support

**Negative:**
- All ingestion is async — callers must poll for completion (already solved: job status endpoint + notification events)
- OCI import adds a thin layer on top rather than being eliminated entirely (justified: OCI resolution is network-bound and benefits from being at the API edge)

## Affected Code

| File | Change |
|------|--------|
| `internal/store/handlers_import.go` | Remove `rawBodyImport`, `importPolicyFromArtifactBody`, `importCatalogFromArtifactBody`. Keep OCI import as wrapper. |
| `internal/store/ingest_handler.go` | Remove legacy sync ingest handler; single handler accepts all artifact types and returns job IDs as needed. |
| `internal/store/ingest_worker.go` | Expand `IngestWorker` to handle Policy, Catalog, Mapping in addition to EvaluationLog/EnforcementLog. |
| `internal/store/populate.go` | Remove startup catalog populate helpers tied to deprecated seed flows. |
| `internal/store/handlers.go` | Remove legacy evidence-only ingest route; expose `/api/ingest` and `/api/ingest/jobs/{job_id}`. |
| `internal/events/nats.go` | Rename subjects to `core.*` namespace. Remove `SubjectEvidence` alias where obsolete. |
| `deploy/compose/docker-compose.yaml` | Single `seed` container replaces split seed patterns where applicable. |
