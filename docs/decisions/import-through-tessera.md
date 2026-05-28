# OCI Import Routes Through Tessera

**Status:** Accepted
**Date:** 2026-05-26

## Decision

The `POST /api/import` endpoint routes each artifact from an OCI bundle through Tessera before async processing, matching the `/api/ingest` path. The response changes from `201 Created` (synchronous) to `202 Accepted` (asynchronous). A legacy fallback preserves synchronous behavior when Tessera is not configured.

## Context

The import endpoint previously bypassed Tessera entirely: it pulled an OCI bundle, parsed each artifact, and inserted directly into PostgreSQL. This meant imported policies had no `tessera_log_index`, were invisible to the witness, and couldn't be referenced by evidence submissions using log_index.

With policy enrollment depending on dimension matching against policies with `tessera_log_index`, and the witness needing to verify all artifacts, the bypass created a gap where imported policies were second-class citizens.

## How It Works

```
POST /api/import {"reference": "ghcr.io/org/policies/baseline:v2.0.0"}
    ↓
Gateway pulls OCI bundle
    ↓
For each artifact in bundle:
    ├─ Tessera append → log_index
    ├─ NATS publish (with bundle_id + oci_reference)
    └─ Worker processes async (same as /api/ingest path)
    ↓
Response: 202 Accepted {bundle_id, status: "processing", digest, artifacts}
```

All artifacts in a bundle share a `bundle_id`, tracked in the `bundle_artifacts` table. This enables reconstructing the full bundle for effective policy resolution — the complete set of requirements derived from a Policy plus its imported ControlCatalogs, ThreatCatalogs, and Mappings.

## Breaking Change: 201 → 202

The import endpoint previously returned `201 Created` with the list of imported artifacts (synchronous). It now returns `202 Accepted` with a `bundle_id` for tracking (asynchronous). Callers that depended on synchronous completion need to poll job status or subscribe to NATS events.

**Mitigation:** When `TesseraAppender` is nil (Tessera not configured), the handler falls back to the legacy synchronous path and returns `201 Created`. This preserves backward compatibility for deployments that haven't enabled Tessera.

## Publisher Identity for Imports

Imported artifacts receive a synthetic publisher identity:
- `sub`: `import:{oci_reference}` (e.g., `import:ghcr.io/org/policies/baseline:v2.0.0`)
- `issuer`: `complytime-gateway`
- `type`: `import`

This distinguishes imported artifacts from directly ingested ones in the witness trust model.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Keep import synchronous, add Tessera inline | Blocks HTTP response on Tessera append + NATS publish for every artifact in bundle |
| Separate Tessera-aware import endpoint | Two import paths to maintain; confusing API surface |
| Deprecate import, require /api/ingest only | Breaks OCI bundle workflow; teams would need to extract and submit each artifact individually |

## Related

- [Transparency Ledger](transparency-ledger.md) — all artifacts now flow through Tessera
- [Unified Ingest Pipeline](unified-ingest-pipeline.md) — import now uses the same async pipeline
- [Policy Enrollment](policy-enrollment.md) — requires policies to have tessera_log_index
