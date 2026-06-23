# Public API Boundary

**Status:** Accepted (revised 2026-06-23)
**Date:** 2026-06-19

## Decision

All endpoints except `/healthz` require authentication via Cedar authorization. Routes under `/api/` and `/workbench/` are authenticated on the primary listener `:8080`. Transparency log read endpoints (`/checkpoint`, `/tile/*`, `/log/witnessed/:index`) are also authenticated on `:8080`. An internal listener on `:8081` serves tlog reads without authentication for the witness service only. Operational endpoints (`/healthz`) remain unauthenticated on both listeners.

## Context

The original decision treated transparency logs like Certificate Transparency (public reads). However, compliance evidence contains sensitive data—vulnerability scans, control assessments, security posture information. The relying parties (auditors, witnesses, tooling) are a known set who can authenticate.

Authorization is enforced via Cedar policies (`.cedar` files in the repo with hot-reload). Dynamic entity data (publisher trust attributes) flows from NATS KV. The system uses two listeners:

- **:8080 (primary, authenticated)** — Serves all routes; Cedar policies enforce read/write authorization
- **:8081 (internal, unauthenticated)** — Serves only tlog read endpoints for the witness service (host-only, no network exposure)

Read access is split by sensitivity:
- `read:checkpoint` — Log metadata (new checkpoint available, size, timestamp), required for any authenticated identity
- `read:entries` — Evidence content (security artifacts, assessment data), requires auditors group membership

## Authenticated Endpoints (:8080, Cedar policies)

| Path | Purpose | Authorization requirement |
|:--|:--|:--|
| `GET /checkpoint` | Cosigned checkpoint (signed note) | `read:checkpoint` (any authenticated identity) |
| `GET /tile/*` | Merkle tree tiles + entry bundles | `read:entries` (auditors group) |
| `GET /log/witnessed/:index` | Witnessed status by log index | `read:checkpoint` (any authenticated identity) |
| `GET /api/evidence/*` | Evidence queries | `read:entries` (auditors group) |
| `POST /api/ingest` | Evidence submission (writes to log) | `submit` (any authenticated identity; publisher trust enforced at handler via JWT) |
| `/api/targets/*` | Target management | `admin` |
| `/api/users/*`, `/api/role-changes/*` | User administration | `admin` |
| `/api/config` | Application config | `admin` for write, `read:checkpoint` for public read |
| `/workbench/*` | UI proxy | `read:entries` (auditors group) |

## Unauthenticated Endpoints

| Listener | Path | Purpose |
|:--|:--|:--|
| `:8080` and `:8081` | `GET /healthz` | Liveness probe (all health checks) |
| `:8081` only | `GET /checkpoint` | Cosigned checkpoint for witness service |
| `:8081` only | `GET /tile/*` | Merkle tree tiles for witness service |
| `:8081` only | `GET /log/witnessed/:index` | Witnessed status for witness service |

## Security Properties

| Property | Threat | Control |
|:--|:--|:--|
| Log metadata protection | Checkpoint size and timing disclose log growth patterns (T-INFO-02) | Authenticated read via `read:checkpoint` |
| Evidence confidentiality | Unauthenticated reads expose vulnerability scans, control assessments (T-INFO-03) | Authenticated read via `read:entries`, authorization gated by auditors group |
| Ingestion integrity | Unauthenticated writes allow evidence flooding and spoofing | Cedar `submit` action required for `/api/ingest`, publisher trust enforced at handler via JWT issuer/subject matching, rate limiting (CTRL-OI-03) |
| Witness availability | Public endpoints overwhelmed via DDoS (T-DOS-02) | Separate internal listener (:8081) for witnesses, isolated from internet traffic; rate limiting on authenticated endpoints |
| Non-equivocation | Independent verification blocked if reads require authentication | Witness service uses internal :8081 listener (no auth), still verifies cosignatures independently |

## Threat Model

### Mitigated Threats (authenticated tlog reads)

**T-INFO-02: Log metadata disclosure.** Previously accepted risk. Now mitigated by requiring `read:checkpoint` authorization to access `/checkpoint` on :8080. Witness service learns checkpoint size and timing via internal :8081 listener, which is acceptable (witness is trusted infrastructure).

**T-INFO-03: Entry content disclosure.** Previously accepted risk. Now mitigated by requiring `read:entries` authorization (auditors group membership) to access `/tile/*` and evidence entries. Prevents unauthenticated clients from reading vulnerability assessments and security artifacts.

### Accepted Risks

**Witness endpoint access pattern inference.** An observer on the internal network can infer witness activity by observing :8081 traffic patterns (polling frequency, checkpoint size). This is accepted because the witness is deployed in controlled infrastructure and expected to be monitored.

**Authenticated checkpoint timing.** Auditors with `read:checkpoint` authorization can still learn log growth rate. This is accepted because checkpoint reading is necessary for auditors to verify witness cosignatures independently.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Unauthenticated tlog reads (original decision) | Disclosure of checkpoint metadata (T-INFO-02) and evidence content (T-INFO-03) to any attacker. Not acceptable for compliance evidence. |
| Separate public/private log instances | Operational complexity; auditors need the same log for trust verification. |
| Entry-level encryption + public log | Possible future enhancement for highly confidential evidence, but Cedar read authorization is simpler and sufficient today. |
| Witness-in-band on :8080 authenticated endpoint | Witness would need to authenticate (bearer token or mTLS). More complex; dedicated :8081 listener is simpler and allows witness operation without credential management. |

## Related

- [Transparency Ledger](transparency-ledger.md) — the log whose reads are public
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — witnesses and clients that consume public endpoints
- STRIDE threat catalog: `internal/e2e/testdata/transparency-threats.yaml`
