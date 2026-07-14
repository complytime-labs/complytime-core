# 0028 — Async Evidence Ingest: Accept-the-Loss Durability

**Status:** Accepted
**Date:** 2026-05-13
**Related:** Consolidated ingest contract in ADR #0034 (`POST /api/ingest`); this ADR retains the durability model for NATS-assisted ingest.

## Context

The gateway publishes raw Gemara YAML to NATS for background unified ingest processing (`POST /api/ingest` returns `202 Accepted` with `job_id` for polling).

Three durability tiers were evaluated:

| Tier | Mechanism | Guarantees | Complexity |
|:--|:--|:--|:--|
| 1 | NATS core pub/sub + in-memory tracker | At-most-once; state lost on restart | Minimal |
| 2 | NATS JetStream | At-least-once; replay on consumer restart | Moderate — requires stream/consumer config |
| 3 | Postgres WAL-backed outbox | Exactly-once via transactional outbox pattern | High — polling, deduplication, new tables |

## Decision

**Tier 1: accept-the-loss.** NATS core pub/sub with in-memory job tracking.

- If the gateway restarts mid-flight, pending jobs and their YAML payloads are lost.
- Callers can re-submit via `POST /api/ingest` and poll `/api/ingest/jobs/{job_id}`.
- Job status is tracked in a Go `sync.Map`-style structure, not persisted to Postgres.

## Rationale

- The HTTP→worker path is observable through job IDs; callers can distinguish completion from loss.
- JetStream adds operational complexity (stream provisioning, consumer management, retention policies) disproportionate to the current user base.
- The Postgres outbox pattern requires new migration, polling loop, and deduplication logic.
- This decision is explicitly reversible: upgrading to JetStream requires only swapping `Publish` for `PublishMsg` with a stream subject, and replacing the in-memory tracker with a Postgres table.

## Consequences

- **Positive:** Zero new infrastructure. No new migrations. Minimal code surface.
- **Negative:** Job state is ephemeral. Monitoring must account for lost jobs after restarts.
- **Migration path:** When durability becomes a requirement, evaluate JetStream first (lower lift than outbox). Open a new ADR at that point.
