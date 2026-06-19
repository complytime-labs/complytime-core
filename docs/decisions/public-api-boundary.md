# Public API Boundary

**Status:** Accepted
**Date:** 2026-06-19

## Decision

Routes under `/api/` and `/workbench/` require authentication (OAuth2 Proxy headers). All other routes are public. Transparency log read endpoints (`/checkpoint`, `/tile/*`, `/log/witnessed/:index`) and operational endpoints (`/healthz`) are intentionally unauthenticated.

## Context

The gateway serves two categories of traffic:

1. **Transparency log reads** — clients verifying log integrity, computing inclusion proofs, checking witnessed status. These must be public because the security value of a transparency log depends on anyone being able to verify it independently. Requiring authentication would limit verification to authorized parties, defeating the purpose.

2. **Application API** — evidence queries, ingestion, user management, configuration. These require authentication because they access tenant data or mutate state.

The auth middleware enforces this by checking path prefixes:

```go
requiresAuth := strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/workbench/")
```

## Public Endpoints

| Path | Purpose | Why public |
|:--|:--|:--|
| `GET /checkpoint` | Cosigned checkpoint (signed note) | Clients verify log integrity |
| `GET /tile/*` | Merkle tree tiles + entry bundles | Clients compute inclusion proofs |
| `GET /log/witnessed/:index` | Witnessed status by log index | Clients check cosignature coverage |
| `GET /healthz` | Liveness probe | Orchestrator health checks |

## Authenticated Endpoints

| Path prefix | Purpose |
|:--|:--|
| `/api/ingest` | Evidence submission (writes to log) |
| `/api/evidence/*` | Evidence queries |
| `/api/targets/*` | Target management |
| `/api/users/*`, `/api/role-changes/*` | User administration |
| `/api/config` | Application config (exception: public, read-only) |
| `/workbench/*` | UI proxy |

## Security Properties

| Property | Threat | Control |
|:--|:--|:--|
| Log verifiability | Restricting verification to authenticated parties undermines transparency | Public read access to checkpoint, tiles, witnessed status |
| Ingestion integrity | Unauthenticated writes allow evidence flooding and spoofing | Auth required for `/api/ingest`, rate limiting (CTRL-OI-03) |
| Data confidentiality | Unauthenticated reads expose tenant evidence details | Auth required for `/api/evidence/*` and query endpoints |
| Checkpoint enumeration | Attacker learns log size, checkpoint timing, tree growth rate | Accepted risk — this information is intentionally public for verifiability |
| Entry content via tiles | Attacker reads evidence content from entry bundles | Accepted risk — evidence in a transparency log is public by design. If confidential evidence is required, encrypt entries before appending (not currently implemented). |
| Public endpoint flooding | Attacker overwhelms gateway via unauthenticated tlog read endpoints (T-DOS-02) | Infrastructure-level: reverse proxy rate limiting, CDN caching for immutable tiles, network-layer DDoS protection. No application-level rate limiter on public reads. |

## Threat Model

### Accepted Risks (public tlog reads)

**T-INFO-02: Log metadata disclosure.** An unauthenticated client can learn the log's tree size, checkpoint publication frequency, and growth rate by polling `/checkpoint`. This is inherent to transparency logs — the checkpoint is a public commitment to the log state.

**T-INFO-03: Entry content disclosure.** An unauthenticated client can read evidence content from entry bundles served at `/tile/*`. Transparency logs are append-only public ledgers; entries are readable by design. If evidence confidentiality is required, entries must be encrypted before appending — this is not currently implemented and would be a separate ADR.

These risks are accepted because the security value of independent verifiability outweighs the information disclosure. A transparency log that requires authentication to read is not independently verifiable.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Auth on all endpoints | Defeats transparency — only authorized parties could verify the log |
| Separate public/private log instances | Operational complexity for no security gain if entries are the same |
| Entry-level encryption + public log | Correct for confidential evidence, but not needed yet — current evidence is compliance artifacts intended for auditors |

## Related

- [Transparency Ledger](transparency-ledger.md) — the log whose reads are public
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — witnesses and clients that consume public endpoints
- STRIDE threat catalog: `internal/e2e/testdata/transparency-threats.yaml`
