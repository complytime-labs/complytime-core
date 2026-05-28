# Witness Service

**Status:** Accepted
**Date:** 2026-05-23

## Decision

An independent witness service (`cmd/witness`) polls the Tessera transparency log, verifies each entry against multiple trust criteria, and countersigns valid checkpoints. Witness validation for unregistered targets is advisory (log warnings, don't reject) during the enrollment adoption period.

## Context

The Tessera transparency log guarantees immutability and ordering, but not quality. An entry in the log proves "this was submitted at this time" — not "this is valid evidence from a trusted source." The witness adds a second trust layer: independent verification that evidence meets quality and provenance standards.

## Verification Checks

The witness performs these checks for each Tessera entry, in order:

1. **Tessera entry exists** — Read raw YAML from log at index
2. **Gemara artifact type** — Parse metadata.type (Policy, EvaluationLog, etc.)
3. **PostgreSQL certification** — Query evidence by log_index, check certified=true
4. **Publisher trust** — Match publisher issuer/sub against trusted_publishers config (glob patterns)
5. **Target registration** (advisory) — Warn if target.id not in targets table
6. **Policy reference integrity** — Verify referenced policies exist in Tessera and are witnessed
7. **Evidence reference integrity** (AuditLog only) — Verify referenced evidence exists and is witnessed
8. **Target scoping** (AuditLog only) — Verify all referenced evidence targets match the AuditLog target

## Why Advisory for Target Registration

Strict enforcement would block evidence submission for teams that haven't adopted the enrollment system yet. Advisory warnings provide visibility into unregistered targets via witness logs without breaking existing workflows. Switch to strict enforcement once adoption reaches critical mass (measured by counting advisory warnings trending toward zero).

## Deployment

The witness runs as a separate binary (`cmd/witness`) with its own configuration:
- **Config:** YAML file with trusted publisher patterns and poll interval
- **State:** JSON file persisting last verified index and checkpoint hash across restarts
- **Storage:** Read-only access to Tessera PersistentVolume, read-write to PostgreSQL

## Checkpoint Countersigning

The witness stores the Tessera signed checkpoint (sumdb note format) after verifying each entry. The `witnessed_indices.checkpoint_hash` column contains the base64-encoded signed note, which includes the log origin, tree size, and Merkle root hash at verification time.

**Ephemeral signer limitation:** The gateway generates a new ephemeral signer key on each startup. Checkpoint signatures cannot be verified across process restarts. This is acceptable for local-only transparency logs where the witness and gateway share the same POSIX storage. Persistent signer keys (stored in a secret manager) are a follow-up for production multi-node deployments.

The `checkpoint_hash` column schema is forward-compatible — no migration is needed when persistent signers are introduced.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| In-process verification (gateway) | Same trust boundary as evidence submission — defeats the purpose |
| External witness service (separate repo) | Unnecessary separation for internal-only witnesses |
| Blockchain-based verification | Massive operational overhead for no additional benefit over Tessera+witness |

## Deferred: NATS Publisher Identity

**Status:** Documented, implementation deferred to a security-hardening PR.

The current ingest pipeline trusts publisher identity from the NATS message payload. The HTTP handler (`/api/ingest`) extracts publisher identity from the JWT `Authorization` header and commits it to the Tessera log entry. The NATS worker reads it from the event envelope.

**Chosen approach: Envelope wrapping.** Publisher identity is cryptographically committed to the Tessera entry at HTTP ingest time. The NATS worker re-derives identity from the Tessera entry rather than trusting the NATS message. This means:

1. Even if NATS is compromised, the worker reads identity from the immutable Tessera log entry — not the NATS message
2. NATS auth/TLS is a separate production hardening concern (defense-in-depth), not a prerequisite
3. The witness independently verifies publisher trust from the Tessera entry

**What is NOT covered yet:**

- NATS TLS and authentication (NATS credentials, NKey, or JWT-based auth)
- NATS authorization policies (per-subject ACLs)
- Message signing/encryption at the NATS transport layer

These are production deployment concerns and should be addressed in a dedicated security-hardening PR when moving to multi-node deployments.

## Related

- [Transparency Ledger](transparency-ledger.md) — the log that the witness verifies
