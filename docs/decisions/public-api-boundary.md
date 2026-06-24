# Public API Boundary

**Status:** Accepted
**Date:** 2026-06-23

## Decision

All endpoints except `/healthz` require authentication and Cedar authorization. The system uses two listeners:

- **:8080 (primary)** — all routes require OAuth2 Proxy identity + Cedar policy permit
- **:8081 (internal)** — tlog read endpoints only, no auth, bound to `127.0.0.1` by default

Read access is split by sensitivity:

- `read:checkpoint` — log metadata (any authenticated identity)
- `read:entries` — evidence content (requires auditors group)

## Context

Compliance evidence contains sensitive data — vulnerability scans, control assessments, security posture information. The relying parties (auditors, witnesses, tooling) are a known set who can authenticate. Merkle tree integrity does not require public access; it requires that authorized verifiers can check the log independently.

Authorization is enforced via Cedar policies (`.cedar` files with hot-reload). Dynamic entity data (publisher trust) flows from NATS KV. The omniwitness (third-party binary) cannot send auth headers, so it reads checkpoints via the internal listener.

## Endpoints

### Authenticated (:8080, Cedar policies)

| Path | Purpose | Action |
| :-- | :-- | :-- |
| `GET /checkpoint` | Cosigned checkpoint | `read:checkpoint` (any authenticated) |
| `GET /tile/*` | Merkle tree tiles + entry bundles | `read:entries` (auditors group) |
| `GET /log/witnessed/:index` | Witnessed status | `read:checkpoint` (any authenticated) |
| `GET /api/system-info` | Service status | `read:status` (any authenticated) |
| `GET /api/config` | Application config | `read:status` (any authenticated) |
| `GET /api/ingest/jobs/:id` | Ingest job status | `read:status` (any authenticated) |
| `POST /api/ingest` | Evidence submission | `publish` (publishers group; target-scoped trust via Cedar) |
| `POST /api/import` | OCI bundle import | `publish` (publishers group) |

### Unauthenticated

| Listener | Path | Purpose |
| :-- | :-- | :-- |
| Both | `GET /healthz` | Liveness probe |
| `:8081` only | `GET /checkpoint` | Checkpoint for witness |
| `:8081` only | `GET /tile/*` | Tiles for witness |
| `:8081` only | `GET /log/witnessed/:index` | Witnessed status for witness |

## Security Properties

| Property | Threat | Control |
| :-- | :-- | :-- |
| Default-deny posture | New endpoints accessible without auth (T-SPOOF-03) | Cedar default-deny middleware (CTRL-AC-01) |
| Log metadata protection | Checkpoint disclosure (T-INFO-02) | Authenticated `read:checkpoint` (CTRL-AC-02) |
| Evidence confidentiality | Evidence content disclosure (T-INFO-03) | Authenticated `read:entries`, auditors group (CTRL-AC-03) |
| Ingestion integrity | Evidence flooding and spoofing | Cedar `publish` (publishers group + target-scoped trust via Cedar) (CTRL-CI-05) + rate limiting (CTRL-OI-03) |
| Witness isolation | Endpoint flooding (T-DOS-02) | Internal listener on 127.0.0.1 (CTRL-AC-04) |

## Accepted Risks

**Witness access pattern inference.** An observer on the internal network can infer witness activity from :8081 traffic. Accepted — the witness runs in controlled infrastructure.

**Authenticated checkpoint timing.** Auditors with `read:checkpoint` can learn log growth rate. Accepted — checkpoint reading is necessary for verifying witness cosignatures.

**Import path bypasses target-scoped publisher trust (T-SPOOF-04).** The OCI bundle import endpoint (`POST /api/import`) applies the middleware-level publishers group gate but does not perform handler-level target-scoped trust checks. Imported artifacts receive a synthetic publisher identity. Accepted — the publishers group gate limits who can import, and imported evidence is append-only (detectable by the monitor). Target-scoped trust for the import path is tracked for a future release.

## Trust Assumptions

**OAuth2 Proxy is the sole ingress to :8080.** The identity model depends on `X-Forwarded-*` headers set by the proxy. Port 8080 must not be directly exposed; the compose/k8s topology enforces this.

**Internal listener (:8081) serves tiles without authentication.** Network access to this port is equivalent to `read:entries` authorization. The compose network restricts access to the witness container. In production deployments, use k8s network policies or equivalent to limit access to the witness pod.

**Two-layer Cedar authorization for publish.** Middleware evaluates `Action::"publish"` (requires publishers group) as a coarse identity-level gate. The ingest handler then evaluates a sub-action — `publish:artifact` (target-scoped trust), `publish:registration` (any publisher), or `publish:policy` (any publisher) — based on artifact type. The sub-actions are only reachable after the middleware gate passes.

**Cedar forbid rules are non-bypassable safety floors.** The embedded policy includes `forbid/unless` rules for `read:entries` (auditors group), `publish` (publishers group), and `publish:artifact` (target trust). Directory-added policies can add permits for other actions but cannot override these floors.

## Alternatives Considered

| Alternative | Why not |
| :-- | :-- |
| Unauthenticated tlog reads | Exposes compliance evidence to any network observer |
| Separate public/private log instances | Operational complexity; auditors need the same log |
| Entry-level encryption + public log | Simpler to authenticate reads; encryption is a future option for highly confidential evidence |
| Witness on :8080 with credentials | Adds credential management complexity; dedicated internal listener is simpler |

## Related

- [Transparency Ledger](transparency-ledger.md)
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md)
- Threat catalog: `internal/e2e/testdata/transparency-threats.yaml`
- Control catalog: `internal/e2e/testdata/transparency-controls.yaml`
