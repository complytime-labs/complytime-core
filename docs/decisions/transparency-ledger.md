# Transparency Ledger for Evidence and Certification

**Status:** Accepted
**Date:** 2026-05-22 (implemented), 2026-05-27 (ADR updated), 2026-06-18 (witness cosignatures)
**Supersedes:** Original exploratory ADR evaluating Trillian

## Decision

All evidence submissions are appended to a [Tessera](https://github.com/transparency-dev/tessera) transparency log before async processing. Tessera is the source of truth; PostgreSQL is a rebuildable queryable cache. Independent witnesses cosign checkpoints for anti-equivocation detection.

## Context

The original ADR evaluated Trillian as an exploratory option and deferred the decision. Since then, [Tessera](https://github.com/transparency-dev/tessera) — Trillian's successor from the same transparency-dev team — reached v1.0. Tessera provides the same cryptographic guarantees (Merkle tree, append-only, inclusion/consistency proofs) with a simpler operational model: POSIX file storage instead of requiring MySQL/CockroachDB.

Tessera is a Go library, not a standalone daemon. The gateway embeds Tessera directly — it is the log "personality" that defines what entries mean, how they are authenticated, and how the storage directory is served over HTTP. There is no separate Tessera process to deploy.

The platform migrated from ClickHouse to PostgreSQL before this work. The transparency log addresses the same gap identified in the original ADR: PostgreSQL is a mutable store with no structural guarantee against retroactive modification.

## Architecture

```text
POST /api/ingest (JWT verified)
    ↓
Gateway (embeds Tessera library) → append → sequential log_index
    ↓ WithWitnesses: witnesses verify consistency + cosign checkpoint
    ↓
NATS core.ingest (async)
    ↓
IngestWorker → PostgreSQL (with log_index column)
    ↓
CertificationHandler → trust signals

tlog-tiles read API (public, no auth, served by gateway from POSIX storage):
    GET /checkpoint       → cosigned checkpoint (signed note)
    GET /tile/*           → Merkle tree tiles + entry bundles
    GET /log/witnessed/:index → witnessed status by log index

Content monitor (cmd/monitor, independent daemon):
    ↓ polls Tessera storage
    ├─ Verify certification passed
    ├─ Verify publisher trusted (JWT issuer/sub vs config)
    ├─ Verify reference integrity (policy refs, evidence refs)
    └─ Advisory: check target registered
```

## Why Tessera over Trillian

| Property | Trillian | Tessera |
|:--|:--|:--|
| Integration model | Standalone gRPC server | Go library embedded in application |
| Storage backend | MySQL or CockroachDB | POSIX filesystem (PersistentVolume) |
| Operational complexity | High (separate database + process) | Low (directory on disk, no extra process) |
| Cryptographic guarantees | Merkle tree, signed tree heads | Same (successor library) |
| Maintained by | transparency-dev (Google) | Same team |
| Go API | Stable | Stable (v1.0) |

## Key Design Decisions

**Gateway embeds Tessera.** The gateway binary is the log personality — it imports Tessera as a Go library, calls `tessera.NewAppender` to create the log, and serves the POSIX storage directory over HTTP at `/checkpoint` and `/tile/*`. There is no separate Tessera daemon.

**PostgreSQL is a cache, not the source of truth.** The `log_index` column on the `evidence` table links each row to its Tessera entry. PostgreSQL can be rebuilt by replaying the Tessera log.

**POSIX storage for cloud-agnostic deployment.** Tessera writes to a directory on disk, mountable as a Kubernetes PersistentVolume. No cloud-specific storage driver required.

**Persistent signer key (opt-in).** When `TESSERA_SIGNER_KEY_PATH` is set, the signer key is loaded from (or generated into) that file so the log maintains a stable identity across restarts and checkpoint signatures remain verifiable. When unset, an ephemeral key is generated per instance.

**Witness cosignatures via Tessera WithWitnesses.** When `TESSERA_WITNESS_POLICY_PATH` is set, the appender collects cosignatures from independent witnesses before publishing checkpoints. The witness policy uses the [Sigsum policy format](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md) and supports quorum thresholds (e.g., 2-of-3). `TESSERA_WITNESS_FAIL_OPEN` (default: false) controls whether checkpoints publish without satisfied quorum; set `true` only during initial rollout.

**Standard tlog-tiles read API.** The gateway serves the Tessera POSIX storage directory over HTTP at `/checkpoint` and `/tile/*`, following the [C2SP tlog-tiles specification](https://c2sp.org/tlog-tiles). Clients fetch the checkpoint and tiles to compute and verify inclusion proofs offline — no server-side proof computation needed.

**Witnessed-status endpoint.** `GET /log/witnessed/:index` reports whether a given log index is covered by a witnessed (cosigned) checkpoint. Clients that need only a yes/no answer don't have to parse the checkpoint and count cosignatures.

**Content monitor (`cmd/monitor`).** An independent service polls Tessera, verifies entry quality (Gemara schema, publisher trust, reference integrity), and produces verification attestations for verified evidence. See [Content Verification Service](content-verification-service.md). Target registration checks are advisory during adoption.

**Anti-equivocation witnesses cosign checkpoints.** Independent tlog witnesses verify log consistency and cosign checkpoints via the C2SP tlog-witness protocol. See [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md).

## Operating a Witness

### Quick start (development)

For local development, run [`transparency-dev/witness`](https://github.com/transparency-dev/witness) with a local SQLite database:

```bash
# Generate witness keys and policy
./scripts/setup-witness.sh

# Start the stack (gateway + witness + postgres + nats)
cd deploy/compose && docker compose up
```

The development witness runs a real `transparency-dev/witness` instance configured against the local log. It verifies consistency proofs before cosigning — the same protocol used in production, just running locally with an ephemeral SQLite state database.

### Production

A production witness must:

1. **Run in a separate trust domain** from the log (different host, operator, key custody).
2. **Verify consistency proofs** before cosigning — the witness checks that the new checkpoint is consistent with its previously stored checkpoint, confirming the log only grew and never forked.
3. **Use a stable key pair** managed via HSM or sealed storage.

Recommended implementations:
- [`transparency-dev/witness`](https://github.com/transparency-dev/witness) — reference implementation, supports the `c2sp.org/tlog-witness` protocol, SQLite state
- [`FiloSottile/litetlog`](https://github.com/FiloSottile/litetlog) `litewitness` — lightweight alternative, SQLite + ssh-agent

### Quorum policy

The witness policy file uses the [Sigsum policy format](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md):

```text
witness alice <verifier-key> https://witness-alice.example.com/
witness bob   <verifier-key> https://witness-bob.example.com/
group quorum 2 alice bob
quorum quorum
```

- `witness <name> <vkey> <url>` defines a witness endpoint
- `group <name> <threshold> <children>` defines a quorum group
- `quorum <name>` designates the root policy

Start with 1-of-1 and move to 2-of-3 as more witnesses come online.

### Security claim

> Tamper-evident and append-only always. Equivocation is **detectable** when at least one honest independent witness cosigns checkpoints: a witness that observes an inconsistent checkpoint refuses to cosign, and clients that verify cosignatures detect the absence or conflict. The strength of the guarantee scales with witness independence — more witnesses in distinct trust domains means more parties must be compromised for equivocation to go undetected.

### Configuration

| Variable | Default | Description |
|:--|:--|:--|
| `TESSERA_WITNESS_POLICY_PATH` | (empty) | Path to Sigsum policy file. Empty = no witnesses. |
| `TESSERA_WITNESS_TIMEOUT` | `5s` | Max wait for witness cosignatures. |
| `TESSERA_WITNESS_FAIL_OPEN` | `false` | Fail-closed by default when a witness policy is configured. Set `true` only during initial rollout. |

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Trillian | Requires MySQL/CockroachDB + separate gRPC server — unnecessary operational complexity |
| Sigstore Rekor | Hosted service, designed for software supply chain not compliance evidence |
| S3 Object Lock | No Merkle tree, no inclusion proofs, no independent verifiability |
| Application-layer hash chain | No external witness, rewritable by anyone with DB access |
| Do nothing | Auditors cannot independently verify evidence integrity |

## Related

- [Hash-Chained Audit Provenance](audit-provenance-deferred.md) — superseded by this decision
- [Unified Ingest Pipeline](unified-ingest-pipeline.md) — all artifacts route through Tessera
- Issue #133 — enable real witness cosignatures + client-verifiable checkpoint reads
- STRIDE threat model: `internal/e2e/testdata/transparency-threats.yaml`
- Control catalog: `internal/e2e/testdata/transparency-controls.yaml`
