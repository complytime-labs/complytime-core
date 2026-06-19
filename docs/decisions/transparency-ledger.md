# Transparency Ledger for Evidence and Certification

**Status:** Accepted
**Date:** 2026-05-22 (implemented), 2026-05-27 (ADR updated)
**Supersedes:** Original exploratory ADR evaluating Trillian

## Decision

All evidence submissions are appended to a [Tessera](https://github.com/transparency-dev/tessera) transparency log before async processing. Tessera is the source of truth; PostgreSQL is a rebuildable queryable cache. An independent witness service verifies log entries and countersigns checkpoints.

## Context

The original ADR evaluated Trillian as an exploratory option and deferred the decision. Since then, [Tessera](https://github.com/transparency-dev/tessera) — Trillian's successor from the same transparency-dev team — reached v1.0. Tessera provides the same cryptographic guarantees (Merkle tree, append-only, inclusion/consistency proofs) with a simpler operational model: POSIX file storage instead of requiring MySQL/CockroachDB.

The platform migrated from ClickHouse to PostgreSQL before this work. The transparency log addresses the same gap identified in the original ADR: PostgreSQL is a mutable store with no structural guarantee against retroactive modification.

## Architecture

```
POST /api/ingest (JWT verified)
    ↓
Tessera append → sequential log_index
    ↓
NATS core.ingest (async)
    ↓
IngestWorker → PostgreSQL (with log_index column)
    ↓
CertificationHandler → evidence.certified

Witness service (independent daemon):
    ↓ polls Tessera
    ├─ Verify certification passed
    ├─ Verify publisher trusted (JWT issuer/sub vs config)
    ├─ Verify reference integrity (policy refs, evidence refs)
    ├─ Advisory: check target registered
    └─ Countersign checkpoint
```

## Why Tessera over Trillian

| Property | Trillian | Tessera |
|:--|:--|:--|
| Storage backend | MySQL or CockroachDB | POSIX filesystem (PersistentVolume) |
| Operational complexity | High (separate database) | Low (directory on disk) |
| Cryptographic guarantees | Merkle tree, signed tree heads | Same (successor library) |
| Maintained by | transparency-dev (Google) | Same team |
| Go API | Stable | Stable (v1.0) |

## Key Design Decisions

**PostgreSQL is a cache, not the source of truth.** The `log_index` column on the `evidence` table links each row to its Tessera entry. PostgreSQL can be rebuilt by replaying the Tessera log.

**POSIX storage for cloud-agnostic deployment.** Tessera uses a directory on disk, mountable as a Kubernetes PersistentVolume. No cloud-specific storage driver required.

**Persistent signer key (opt-in).** When `TESSERA_SIGNER_KEY_PATH` is set, the signer key is loaded from (or generated into) that file so the log maintains a stable identity across restarts and checkpoint signatures remain verifiable. When unset, an ephemeral key is generated per instance (the previous default).

**Witness validation is advisory for target registration.** The witness logs warnings for unregistered targets but does not reject evidence. This allows gradual adoption of the enrollment system.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Trillian | Requires MySQL/CockroachDB — unnecessary operational complexity |
| Sigstore Rekor | Hosted service, designed for software supply chain not compliance evidence |
| S3 Object Lock | No Merkle tree, no inclusion proofs, no independent verifiability |
| Application-layer hash chain | No external witness, rewritable by anyone with DB access |
| Do nothing | Auditors cannot independently verify evidence integrity |

## Related

- [Hash-Chained Audit Provenance](audit-provenance-deferred.md) — superseded by this decision
- [Unified Ingest Pipeline](unified-ingest-pipeline.md) — all artifacts route through Tessera
