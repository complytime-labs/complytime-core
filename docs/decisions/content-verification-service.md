# Content Verification Service

**Status:** Accepted
**Date:** 2026-05-23

## Decision

An independent content verification service (`cmd/monitor`) polls the Tessera transparency log, verifies each entry against quality and provenance criteria, and produces a signed verification attestation (Gemara AuditLog) recording what was verified and the result. This follows the SLSA Verification Summary Attestation (VSA) pattern: verify an artifact against a policy, then produce an independent signed statement of the outcome.

This is distinct from **tlog witnessing** (anti-equivocation), which verifies log consistency and cosigns checkpoints without inspecting content. See [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) for that concern.

## Context

The Tessera transparency log guarantees immutability and ordering, but not quality. An entry in the log proves "this was submitted at this time" — not "this is valid evidence from a trusted source." The content verification service adds a second trust layer: independent verification that evidence meets quality and provenance standards.

## Verification Checks

The service performs these checks for each Tessera entry, in order:

1. **Tessera entry exists** — read raw YAML from log at index
2. **Gemara artifact type** — parse `metadata.type` (Policy, EvaluationLog, etc.)
3. **Trust signal status** — query whether the certification pipeline found failures
4. **Publisher trust** — match publisher `issuer`/`sub` against trusted publisher patterns (glob matching)
5. **Target registration** (advisory) — warn if `target.id` is not registered
6. **Policy reference integrity** — verify referenced policies exist in Tessera and are verified
7. **Evidence reference integrity** (AuditLog only) — verify referenced evidence exists and is verified
8. **Target scoping** (AuditLog only) — verify all referenced evidence targets match the AuditLog target

## Why Advisory for Target Registration

Strict enforcement would block evidence submission for teams that haven't adopted the enrollment system yet. Advisory warnings provide visibility into unregistered targets via logs without breaking existing workflows. Switch to strict enforcement once adoption reaches critical mass (measured by counting advisory warnings trending toward zero).

## Deployment

The service runs as a separate binary (`cmd/monitor`) with its own configuration:
- **Config:** YAML file with trusted publisher patterns and poll interval
- **State:** JSON file persisting last verified index and checkpoint hash across restarts
- **Storage:** Read-only access to Tessera, read-write to PostgreSQL (PostgreSQL dependency being phased out per #128)

## Verification Attestation Output (not yet implemented)

When verification passes, the service produces a signed Gemara AuditLog — a verification attestation recording what was checked and the outcome. This AuditLog flows back through `POST /api/ingest` into Tessera, making the verification result independently verifiable. Currently the service writes a PostgreSQL row (`witnessed_indices`), which is not cryptographically verifiable by an external party.

## NATS Publisher Identity

Publisher identity is cryptographically committed to the Tessera entry at HTTP ingest time. The NATS worker re-derives identity from the Tessera entry rather than trusting the NATS message. This means:

1. Even if NATS is compromised, the worker reads identity from the immutable Tessera log entry
2. NATS auth/TLS is defense-in-depth, not a prerequisite
3. The content verification service independently verifies publisher trust from the Tessera entry

NATS transport security (TLS, credentials, ACLs) is a separate production hardening concern tracked in #37.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| In-process verification (gateway) | Same trust boundary as evidence submission — defeats the purpose |
| Blockchain-based verification | Massive operational overhead for no additional benefit over Tessera + attestation |

## Related

- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — tlog witnesses cosign checkpoints (separate concern)
- [Transparency Ledger](transparency-ledger.md) — the log that the service verifies
