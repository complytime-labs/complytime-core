# 0040 — JetStream Durable Consumer for Ingest Pipeline

**Status:** Accepted
**Date:** 2026-05-28
**Supersedes:** #0028 (Tier 1 accept-the-loss) — upgrades to Tier 2

## Context

ADR #0028 chose NATS core pub/sub (Tier 1) for the async ingest pipeline. Messages and job state are lost on gateway restart. The decision explicitly documented a migration path to JetStream when durability became a requirement.

With Tessera providing the source-of-truth append-only log and the worker performing idempotent inserts keyed by `log_index`, the missing piece is reliable delivery from HTTP handler to worker across restarts.

## Decision

**Tier 2: NATS JetStream** for `core.ingest` subject only.

| Aspect | Choice |
|:--|:--|
| Stream | `INGEST`, subject `core.ingest`, retention `WorkQueue` |
| Consumer | `ingest-worker`, durable pull, explicit ack |
| Max delivery | 5 attempts (configurable via `NATS_INGEST_MAX_DELIVER`) |
| Ack wait | 30s (configurable via `NATS_INGEST_ACK_WAIT`) |
| Message payload | Reference only (`log_index` + metadata) — worker fetches YAML from Tessera |
| Deduplication | `Nats-Msg-Id` set to `job_id` with 2-minute dedupe window |
| Other subjects | `core.evidence.*`, `core.policy.new`, `core.target.registered` remain core pub/sub (fire-and-forget, non-critical) |

### Message Envelope

```json
{
  "job_id": "uuid",
  "log_index": 42,
  "publisher_identity": {"sub": "...", "issuer": "...", "type": "pipeline", "verified": true},
  "bundle_id": "",
  "oci_reference": "",
  "timestamp": "2026-05-28T00:00:00Z"
}
```

YAML is not included in the message. Worker calls `tessera.Read(log_index)` to retrieve the artifact content.

### Ack Semantics

| Worker outcome | Action | Effect |
|:--|:--|:--|
| PG insert success | `msg.Ack()` | Message removed from stream |
| Transient failure (PG timeout, Tessera not-yet-integrated) | `msg.NakWithDelay(5s)` | Redelivered after delay |
| Permanent failure (invalid YAML, unsupported type) | `msg.Term()` | Terminal — no further delivery |

## Rationale

- **Restart safety:** Unacked messages survive gateway restarts. No more lost jobs.
- **Slim messages:** Eliminates the 1MB JetStream default limit concern. Tessera is already the source of truth.
- **Idempotent processing:** PG inserts are keyed by `log_index` — safe for redelivery.
- **Minimal blast radius:** Only `core.ingest` is upgraded. Downstream subjects remain fire-and-forget (loss acceptable for debounced certification triggers).
- **Operational simplicity:** WorkQueue retention auto-removes acked messages. No manual stream management.

## Consequences

- **Positive:** Durable ingest pipeline. Messages replay on restart. Configurable retry with backoff.
- **Negative:** NATS server must run with JetStream enabled (`-js` flag or config). Adds stream/consumer provisioning on startup.
- **Migration path:** Downstream subjects can be upgraded individually if needed — same pattern applies.

## Configuration

| Env Var | Purpose | Default |
|:--|:--|:--|
| `NATS_URL` | NATS server URL (unchanged) | required |
| `NATS_INGEST_MAX_DELIVER` | Max redelivery attempts | `5` |
| `NATS_INGEST_ACK_WAIT` | Ack timeout before redelivery | `30s` |
