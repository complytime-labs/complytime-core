# Evidence Locker Architecture

**Status:** Accepted
**Date:** 2026-07-09

## Decision

Rewrite complytime-core as three microservices in one repository: gateway, locker, and graph. Each service has one job. They communicate over NATS.

- **Gateway** (:8080) — the provenance authority. Authenticates publishers (JWT/OIDC), checks trust (NATS KV, fail-closed), evaluates Cedar authorization policies, wraps artifacts + publisher identity into in-toto v1 receipts, and enqueues work to NATS JetStream. The gateway controls what gets into the locker and binds provenance data to every artifact.
- **Locker** (:8081) — WORM storage. Manages N ledgers (one Tessera transparency log per subject). Seals receipts, serves them by log index, verifies by content digest, and serves tlog-tiles for external verifiers. Internal only — not exposed to the public network.
- **Graph** (:8082) — read-only property graph. Subscribes to NATS events, materializes relationships between evidence, subjects, publishers, and controls. Ingests Gemara MappingDocuments to create cross-framework edges. Memgraph (Cypher) for the experimental phase; production graph queries served by CrossCodex (PostgreSQL + Apache AGE).

A **ledger** is a transparency log for a single subject. Each ledger is an independent Tessera Merkle tree with its own Ed25519 signer, checkpoint, and witness cosignatures. The locker manages N ledgers.

**Operational model: per-subject ledgers with major-version sharding.**

A subject is a fully shipped software system, not a component. This means tens to low hundreds of ledgers, not thousands. At this scale, per-ledger witness cosignatures, storage overhead, and checkpoint intervals are all manageable. This follows the Android Binary Transparency pattern (separate log per software category).

When a product ships a new major version, it gets a new shard (a new Merkle tree). The previous version's shard seals and becomes a read-only archive — a complete, verifiable record of that version's compliance history. This follows the "software autobiography" model: each major version is a chapter with its own evidence trail.

The API doesn't change — `Seal(subject_id, receipt)` routes to the current shard internally, `Fetch(subject_id, index)` resolves the owning shard via an index range lookup. The current `Ledger` struct maps to one shard; the `Locker` manages `subject_id → []*Ledger` (ordered by version) instead of `subject_id → *Ledger` when sharding is implemented.

This pattern draws from Sigstore Rekor (time-based shards) and Android Binary Transparency (per-category logs). Major version sharding is a better fit than time-based sharding for compliance evidence because the compliance lifecycle resets at each major version — re-certification is typically required, making the shard boundary meaningful rather than arbitrary.

For now: one ledger per subject, no sharding. Major-version sharding is the documented growth path.

The locker never sees raw artifacts or raw identities — only receipts the gateway has already bound. The graph does not analyze or score — it answers "what's connected to what" via traversal.

## Context

The previous monolithic design accumulated dead interfaces, dual types, stale ADRs for removed features, unused storage backends, and naming mismatches from multiple architectural pivots. A clean rewrite from a branch off main was less work than gutting the accumulated code. The project is experimental.

## Architecture

```
┌──────────────┐     JetStream      ┌──────────────┐
│   Gateway    │ ──────────────────► │    Locker    │
│   :8080      │                    │    :8081     │
│              │ ◄────── index ──── │              │
└──────┬───────┘                    └──────────────┘
       │                                   ▲
       │  CloudEvent                       │ tlog-tiles
       ▼                                   │
┌──────────────┐                    ┌──────────────┐
│    Graph     │                    │   Witness    │
│    :8082     │                    │  (external)  │
└──────────────┘                    └──────────────┘
```

**Data flow (async, two-step):**

1. Gateway receives artifact + JWT, authenticates, checks trust, wraps receipt, enqueues to JetStream, returns 202.
2. Async worker picks from JetStream, calls locker HTTP API to seal, publishes CloudEvent, acks.

**Push + Pull for consumers:**

- Push: NATS CloudEvents notify consumers that evidence was sealed.
- Pull: consumers fetch sealed receipts from the locker by log index or verify by digest. Richer queries (by subject, time, framework) are served by the graph.

**Trust configuration as evidence:**

Subject registrations and publisher trust changes follow the same ingest path — sealed into the locker for auditability. The locker contains evidence about the evidence pipeline itself.

## Security Properties

| Property | Threat | Control | Test |
|:--|:--|:--|:--|
| Receipts are tamper-evident | Log entries modified after sealing | Tessera Merkle tree + checkpoint signing | ledger_test.go: Seal returns consistent index, Fetch returns exact bytes |
| Publisher identity is bound to artifacts | Artifact origin repudiation | in-toto v1 receipt wrapping | Not yet verified — Gateway (Plan 2) |
| Authorization is fail-closed | Unauthorized evidence submission | NATS KV trust lookup, reject on unavailability | Not yet verified — Gateway (Plan 2) |
| Locker is network-isolated | Direct external access to WORM storage | Docker Compose network isolation, no published ports | docker-compose.yaml: locker has no ports mapping |
| Subject IDs are validated | Path traversal via crafted subject ID | Regex validation `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,253}$` (no dots — NATS safe) | handler_test.go: invalid subject ID tests |

## Alternatives Considered

### Aggressive gut rehab (keep working core, delete the rest)

Rejected because touching almost every file while constantly deciding "does this stay or go" is slower and more error-prone than starting clean with a tight scope. The patterns worth keeping (Tessera integration, receipt wrapping, NATS pipeline, Cedar authz) fit in your head — the code is rewritten, not copied.

### Minimal monolith (one flat internal/ package)

Rejected because it doesn't match the mental model of gateway-in-front, locker-behind. Would hit the "one package does too much" threshold quickly as gateway and graph are added.

## Related

- All ADRs in [adrs/archive/](./archive/) — institutional memory from the previous architecture
