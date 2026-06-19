# Anti-Equivocation Witnessing

**Status:** Accepted
**Date:** 2026-06-18
**Companion to:** [Content Verification Service](content-verification-service.md)

## Decision

Anti-equivocation (detecting when the log operator presents different views to different clients) is provided by independent tlog witnesses that cosign checkpoints via the [C2SP tlog-witness protocol](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md). Content verification (Gemara schema, trust signals, publisher trust) is a separate content monitor that produces verification attestations. These are distinct services with distinct roles.

## Context

Tessera provides a tamper-evident, append-only log. But without independent witnesses, a compromised log operator could present different checkpoint histories to different clients (equivocation). The C2SP tlog-witness protocol addresses this: a witness maintains its own record of the log's last known checkpoint and, when presented with a new checkpoint, verifies a consistency proof before cosigning. If the proof fails — meaning the log forked — the witness refuses to cosign. Clients that verify cosignatures detect the absence or conflict and know the log cannot be trusted.

The content monitor (`cmd/monitor`) verifies entry quality and publisher trust — a different security property. It produces verification attestations (signed AuditLogs), but does not cosign checkpoints or verify log consistency.

## Architecture

Two independent services, each providing a distinct security property:

### Anti-Equivocation Witness (external, tlog-witness protocol)

Verifies log **consistency** — the log only grew and never forked — by checking consistency proofs against its stored state before cosigning. A client verifying cosignatures from independent witnesses can detect equivocation.

- The gateway embeds Tessera as a Go library and uses `WithWitnesses` with a configurable Sigsum witness policy
- The gateway sends new checkpoints to witnesses, which verify consistency proofs against their stored state before cosigning
- Cosigned checkpoints served at `GET /checkpoint` (public, no auth)
- Tiles served at `GET /tile/*` for offline inclusion proof verification
- Witnessed status at `GET /log/witnessed/:index`
- Development: local [`transparency-dev/witness`](https://github.com/transparency-dev/witness) instance with ephemeral SQLite state
- Production: `transparency-dev/witness` or [`litewitness`](https://github.com/FiloSottile/litetlog) in a separate trust domain

### Content Monitor (`cmd/monitor`)

Verifies entry **content** — the artifact is well-formed, from a trusted publisher, with valid references. Produces verification attestations (signed AuditLogs) for verified evidence.

- Polls Tessera for new entries
- Checks: Gemara schema, publisher trust (issuer/sub glob matching), policy reference integrity, evidence reference integrity (AuditLog), target scoping
- Advisory for target registration (log warnings, don't reject)
- See [Content Verification Service](content-verification-service.md) for full details

## Security Properties

| Property | Provided by | Mechanism |
|:--|:--|:--|
| Tamper-evident, append-only | Tessera (embedded in gateway) | Merkle tree, signed checkpoints |
| Non-equivocation (fork detection) | Independent witness | Consistency proof verification + cosigned checkpoints (cosignature/v1) |
| Content quality | Content monitor | Schema, provenance, publisher trust checks + verification attestation |
| Offline client verification | tlog-tiles API | Checkpoint + tiles → inclusion proof |

### Security Claim

> Tamper-evident and append-only always. Equivocation is **detectable** when at least one honest independent witness cosigns checkpoints: a witness that observes an inconsistent checkpoint refuses to cosign, and clients that verify cosignatures detect the absence or conflict. The strength of the guarantee scales with witness independence.

## Configuration

| Variable | Default | Description |
|:--|:--|:--|
| `TESSERA_SIGNER_KEY_PATH` | (empty) | Persistent signer key. Empty = ephemeral (not recommended). |
| `TESSERA_WITNESS_POLICY_PATH` | (empty) | Sigsum witness policy file. Empty = no witnesses. |
| `TESSERA_WITNESS_TIMEOUT` | `5s` | Max wait for cosignatures. |
| `TESSERA_WITNESS_FAIL_OPEN` | `false` | Fail-closed by default when a witness policy is configured. Set `true` only during rollout. |

## Threat Model

Threats and controls are defined as Gemara Layer 2 catalogs with Ginkgo BDD specs as Layer 5 assessments:

- `internal/e2e/testdata/transparency-threats.yaml` — STRIDE threat catalog
- `internal/e2e/testdata/transparency-controls.yaml` — control catalog with assessment requirements
- `internal/e2e/witness_cosign_test.go` — Ginkgo specs verifying security properties

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Build custom cosigning protocol | Tessera + C2SP tlog-witness already exist and are battle-tested |
| Skip witnessing, trust the log operator | Defeats the purpose of a transparency log for compliance |
| FIPS-validated cosignature algorithms | Blocked on upstream (Ed25519-only in cosignature/v1). Tracked in #135. |

## Related

- [Transparency Ledger](transparency-ledger.md) — the log that witnesses verify
- #133 — parent issue for witness cosignatures
- #134 — implementation (witness cosignatures, tlog-tiles, STRIDE threat model)
- #135 — FIPS checkpoint/cosignature algorithm compliance (deferred)
- #136 — Air-gap zero-egress deployment profile (deferred)
