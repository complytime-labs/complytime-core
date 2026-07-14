# Remove PostgreSQL — ComplyTime Ingest

**Status:** Accepted
**Date:** 2026-06-19
**Supersedes:** [Modulith Gateway Architecture](backend-architecture.md)

## Decision

Remove PostgreSQL from complytime-core entirely. Tessera is the source of truth. Publisher trust state moves to NATS KV. Certification results are NATS events. All query endpoints move to CrossCodex. The gateway binary is renamed to `cmd/ingest`.

## Context

complytime-core started as a monolith: ingest, store, query, certify, and manage users — all in one binary backed by PostgreSQL. The transparency ledger (Tessera) made PostgreSQL a rebuildable cache, but the codebase still depends on it for publisher trust lookups, user roles, certification results, and query endpoints.

Issue #128 designs the evolution to ComplyTime Ingest — a focused ingestion and trust boundary service. This ADR removes the PostgreSQL dependency as the first concrete step.

## Architecture

```text
cmd/ingest (renamed from cmd/gateway):
    POST /api/ingest
        → JWT verify (stateless, JWKS)
        → Publisher trust check (NATS KV, fail-closed)
        → Tessera append (embedded library)
        → NATS CloudEvents publish
    
    tlog-tiles read API (public, no auth):
        GET /checkpoint, GET /tile/*, GET /log/witnessed/:index

cmd/monitor (existing, Postgres dependency removed):
    Polls Tessera → runs certification checks → publishes results to NATS
```

Two binaries, same repo. No PostgreSQL in either.

## What Replaces PostgreSQL

| Current (PostgreSQL) | New | Mechanism |
|:--|:--|:--|
| `target_trusted_publishers` table | NATS KV bucket `publisher-trust` | Key: `targets.<target_id>`, value: JSON publisher allowlist |
| `evidence` table (38+ columns) | Removed | Tessera is source of truth. CrossCodex subscribes to NATS events and builds its own read model. |
| `users` + `role_changes` tables | Removed | Role-based write protection replaced by per-target publisher allowlist. JWT authenticates, allowlist authorizes. |
| `trust_signals` table | NATS events | Monitor publishes certification results to durable JetStream stream. |
| Policy, catalog, mapping, target tables | Removed | Query endpoints move to CrossCodex. |
| `witnessed_indices` table | Removed | Superseded by checkpoint-based witnessed status in `tileserver.go`. |

## Authorization Model Change

**Before:** OAuth2 Proxy authenticates → gateway checks user role (reader/writer/admin) in PostgreSQL → writer/admin can POST to `/api/ingest`.

**After:** JWT authenticates the caller → ingest service checks artifact-level authorization based on the artifact category:

| Artifact category | Artifacts | Authorization | Allowlist |
|:--|:--|:--|:--|
| **Governance** | Policy, ControlCatalog, ThreatCatalog, RiskCatalog, GuidanceCatalog, MappingDocument | Governance publisher allowlist | Separate NATS KV bucket (not yet implemented) |
| **Evidence** | EvaluationLog, EnforcementLog, AuditLog | Per-target publisher allowlist | NATS KV `publisher-trust` bucket, deny by default |
| **Target registration** | TargetRegistration | First-registrant or existing target publisher | Self-registration with ownership (not yet implemented) |

This is finer-grained than the old role-based model: a `writer` role authorized everything, while the new model authorizes by artifact category and target. A publisher trusted for target A cannot submit evidence for target B. A pipeline that produces evidence cannot modify governance artifacts.

**Currently implemented:** Evidence publisher trust check (deny by default). Governance and target registration authorization are tracked as follow-on work.

## Fail-Closed Authorization

When NATS KV is unavailable, the ingest service rejects all submissions with HTTP 503 rather than accepting without authorization. Rationale: Tessera is append-only — bad evidence cannot be removed. Integrity must take precedence over availability.

## Publisher Trust State Rebuild

The NATS KV `publisher-trust` bucket is a materialized view of TargetRegistration entries in Tessera. On startup (or after bucket loss), the ingest service replays all TargetRegistration entries from Tessera to rebuild the KV state. No external state is required.

## API Surface

**Keep:**
- `POST /api/ingest` — evidence submission
- `POST /api/import` — bundle unpacker
- `GET /api/ingest/jobs/:job_id` — job status
- `GET /api/config` — application config
- `GET /api/system-info` — system status
- `GET /healthz` — liveness (checks NATS, not Postgres)
- `GET /checkpoint`, `GET /tile/*`, `GET /log/witnessed/:index` — tlog-tiles

**Remove:**
- All evidence, policy, catalog, audit, mapping, target query endpoints
- User management (`/api/users/*`, `/api/role-changes/*`)
- Coverage and requirements matrix endpoints

## Security Properties

| Property | Threat | Mechanism | Fail mode |
|:--|:--|:--|:--|
| Publisher trust at ingest boundary | T-SPOOF-01, T-TAMP-03 | NATS KV lookup matched against JWT iss/sub | Fail-closed: reject if KV unavailable |
| Publisher trust rebuildable | T-TAMP-03 | Startup Tessera replay into NATS KV | Blocks startup until complete |
| Artifact-level authorization | T-ELEV-02 | JWT + per-target publisher allowlist | No allowlist = no submission for that target |
| Certification durability | T-REP-04 | NATS JetStream durable streams | Downstream subscriber persists |

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Keep Postgres for publisher trust only | Still an operational dependency for a single table. NATS KV is simpler and already required for JetStream. |
| Keep role-based write protection | Blunt instrument — authorizes everything or nothing. Publisher allowlist is per-target. |
| Fail-open on KV unavailability | Append-only log means bad evidence is permanent. Integrity over availability. |
| Remove PostgreSQL incrementally | Considered, but the dependencies are tightly coupled. Removing query endpoints, user management, and certification storage together is cleaner than partial extraction. |

## Related

- [Transparency Ledger](transparency-ledger.md) — Tessera as source of truth
- [Public API Boundary](public-api-boundary.md) — what's public vs authenticated
- [Modulith Domain Packages](modulith-domain-packages.md) — superseded by this split
- Issue #128 — ComplyTime Ingest design
- STRIDE threat catalog: `internal/e2e/testdata/transparency-threats.yaml`
- Control catalog: `internal/e2e/testdata/transparency-controls.yaml`
