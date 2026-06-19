<!-- SPDX-License-Identifier: Apache-2.0 -->

# ComplyTime Ingest Architecture

Compliance evidence ingestion and transparency service. Accepts Gemara artifacts via JWT-authenticated API, appends to a Tessera transparency log, publishes CloudEvents to NATS. No PostgreSQL. All query and analysis capabilities are in downstream services (CrossCodex).

## System Overview

| Boundary | Role | Tech | Repository |
|:--|:--|:--|:--|
| **Ingest Service** | Evidence ingestion, Tessera log, publisher trust, tlog-tiles API | Go (Echo), Tessera (embedded), NATS JetStream + KV | [complytime-core](https://github.com/complytime-labs/complytime-core) |
| **Content Monitor** | Independent verification: schema, publisher trust, reference integrity | Go (standalone binary), Tessera (read) | [complytime-core](https://github.com/complytime-labs/complytime-core) |
| **CrossCodex** | Query and analysis: evidence queries, coverage, policy management, graph | TBD | [crosscodex](https://github.com/complytime-labs/crosscodex) |

**Upstream tools** (produce artifacts consumed by ingest):

| Tool | Role | Repository |
|:--|:--|:--|
| **complyctl** | CLI: pulls policies from OCI, scans targets, produces Gemara EvaluationLogs | [complyctl](https://github.com/complytime/complyctl) |
| **complypack** | Policy authoring: validate, test, package assessment logic as signed OCI artifacts | [complytime/issues/8](https://github.com/complytime/complytime/issues/8) |

```mermaid
flowchart TB
  subgraph Clients
    complyctl["complyctl"]
    CI["CI/CD Pipelines"]
  end

  subgraph Ingest["Ingest Service — cmd/gateway — :8080"]
    Echo["Echo — auth, /api/ingest, tlog-tiles"]
  end

  Tessera[("Tessera (POSIX storage)")]
  NATS[("NATS JetStream + KV")]
  Witness["Witness (omniwitness)"]

  subgraph Monitor["Content Monitor — cmd/monitor"]
    WS["Poll Tessera → verify → publish attestation"]
  end

  subgraph Downstream["Downstream Subscribers"]
    CrossCodex["CrossCodex"]
    Other["Other services"]
  end

  complyctl -->|"JWT"| Echo
  CI -->|"JWT"| Echo
  Echo --> Tessera
  Echo --> NATS
  Tessera --> Witness
  WS --> Tessera
  NATS --> Downstream
```

## Binaries

### Ingest Service (`cmd/gateway`)

Accepts Gemara artifacts, appends to Tessera, publishes NATS events. Serves the tlog-tiles read API for offline verification.

| Concern | Implementation |
|:--|:--|
| HTTP | Echo — single listener, middleware stack |
| Transparency | Tessera — embedded Go library, POSIX storage, cosigned checkpoints |
| Publisher trust | NATS KV bucket `publisher-trust` — fail-closed authorization |
| Target registry | NATS KV bucket `targets-registry` |
| Events | NATS JetStream — async ingest worker, evidence/policy/target events |
| Auth | JWT bearer (OIDC JWKS) + OAuth2 Proxy `X-Forwarded-*` headers |
| tlog-tiles | `/checkpoint`, `/tile/*`, `/log/witnessed/:index` — public, no auth |

**Hard requirements:** `NATS_URL` must be set and reachable.

### Content Monitor (`cmd/monitor`)

Independent verification daemon that polls Tessera and validates evidence quality.

| Concern | Implementation |
|:--|:--|
| Verification | Schema validation, publisher trust, reference integrity, target registration (advisory) |
| Config | YAML file with trusted publisher patterns and poll interval |
| State | JSON file persisting last verified index across restarts |

**Hard requirements:** `TESSERA_PATH` must be set.

## Authentication

| Mode | Condition |
|:--|:--|
| **OAuth2 Proxy** | Sidecar handles OIDC, session cookies. Ingest reads `X-Forwarded-Email/User/Groups`. |
| **JWT Bearer** | `POST /api/ingest` accepts OIDC JWT tokens verified via JWKS discovery. For CI/CD pipelines and scanning tools. |
| **No proxy** | `/api/*` returns 401 without `X-Forwarded-Email`. |

No role-based write protection. Authorization is per-target publisher allowlist in NATS KV.

## Data Flow

```mermaid
sequenceDiagram
  participant C as Client
  participant I as Ingest Service
  participant T as Tessera
  participant KV as NATS KV
  participant N as NATS JetStream
  participant W as Witness
  participant M as Monitor

  C->>I: POST /api/ingest (YAML + JWT)
  I->>I: Verify JWT
  I->>KV: Check publisher trust (fail-closed)
  I->>T: Append to log → log_index
  T->>W: Witness cosigns checkpoint
  I->>N: publish core.ingest
  I->>C: 202 Accepted {job_id, log_index}
  N->>I: worker detects artifact type
  I->>N: publish core.evidence / core.policy / core.target
  I->>KV: update publisher trust (TargetRegistration)
  M->>T: poll for new entries
  M->>M: verify schema, publisher, references
  M->>N: publish verification attestation
```

## Key Routes

| Method | Path | Notes |
|:--|:--|:--|
| GET | `/healthz` | NATS connectivity check |
| GET | `/checkpoint` | Cosigned checkpoint (public) |
| GET | `/tile/*` | Merkle tree tiles + entry bundles (public) |
| GET | `/log/witnessed/:index` | Witnessed status by log index (public) |
| GET | `/api/config` | Non-secret config (public) |
| POST | `/api/ingest` | Gemara artifact ingest (async, 202, JWT auth) |
| GET | `/api/ingest/jobs/{job_id}` | Poll ingest job status |
| POST | `/api/import` | OCI bundle import (routes through Tessera) |
| GET | `/api/system-info` | System status |
| GET | `/auth/me` | Current user identity |

## NATS Subjects

| Subject | Use |
|:--|:--|
| `core.ingest` | Async ingest worker (JetStream durable consumer) |
| `core.evidence.<policy_id>` | Evidence ingested for a policy |
| `core.policy.new` | New Policy artifact ingested |
| `core.target.registered` | New TargetRegistration ingested |

## NATS KV Buckets

| Bucket | Key | Value | Purpose |
|:--|:--|:--|:--|
| `publisher-trust` | `targets.<target_id>` | JSON array of publisher allowlist entries | Authorization at ingest boundary |
| `targets-registry` | `<target_id>` | JSON target registration | Target metadata |

Both are materialized views of TargetRegistration entries in Tessera. Rebuildable from the log on bucket loss.

## Configuration

| Variable | Required | Purpose |
|:--|:--|:--|
| `NATS_URL` | Yes | Event bus and KV store |
| `TESSERA_PATH` | No | Transparency log directory (default: `/data/tessera`) |
| `TESSERA_SIGNER_KEY_PATH` | No | Persistent signer key |
| `TESSERA_CHECKPOINT_INTERVAL` | No | Checkpoint publish interval (default: 10m) |
| `TESSERA_WITNESS_POLICY_PATH` | No | Sigsum witness policy file |
| `TESSERA_WITNESS_TIMEOUT` | No | Max wait for cosignatures (default: 5s) |
| `TESSERA_WITNESS_FAIL_OPEN` | No | Fail-closed by default (default: false) |
| `JWT_ISSUERS` | No | Comma-separated allowed JWT issuers |
| `JWT_AUDIENCE` | No | Expected JWT audience claim |
| `PORT` | No | Listen port (default: 8080) |
| `CORS_ORIGINS` | No | Comma-separated allowed origins |

## Removed Query Endpoints (moved to CrossCodex)

The following endpoints were removed in ADR 0044. CrossCodex or other downstream subscribers should implement these as NATS subscribers with their own read models:

| Endpoint | Purpose | NATS subject to subscribe |
|:--|:--|:--|
| `GET /api/evidence` | Query evidence by target, policy, date | `core.evidence.>` |
| `GET /api/policies`, `GET /api/policies/{id}` | Policy CRUD | `core.policy.new` |
| `GET /api/policies/discover` | Dimension-based policy discovery | `core.policy.new` |
| `GET /api/targets` | List registered targets | `core.target.registered` |
| `GET /api/catalogs` | List catalogs | `core.ingest` (filter by type) |
| `GET /api/requirements` | Requirements matrix | Derived from policies + evidence |
| `GET /api/posture` | Posture aggregates | Derived from evidence + trust signals |
| `GET /api/audit-logs`, `POST /api/audit-logs` | Audit log CRUD | `core.ingest` (filter AuditLog) |
| `GET /api/draft-audit-logs` | Draft audit logs | `core.ingest` (filter by type) |
| `POST /api/audit-logs/promote` | Promote draft to official | Was Postgres-only |
| `GET /api/mappings` | Framework mappings | `core.ingest` (filter MappingDocument) |
| `GET /api/threats`, `GET /api/risks` | Threat/risk catalogs | `core.ingest` (filter by type) |
| `GET /api/inventory` | Evidence inventory | Derived from evidence |
| `GET /api/users/*` | User management | Removed (no role-based access) |
| `GET /api/role-changes/*` | Role change history | Removed (no role-based access) |
| `GET /api/certifications` | Certification results | Monitor publishes to NATS |

## Testing

```bash
# Unit tests
go test -tags dev ./...

# Smoke test (requires docker compose stack)
./scripts/setup-witness.sh
cd deploy/compose && docker compose up --build -d
cd ../.. && ./scripts/smoke-test.sh

# Integration tests (Ginkgo, in-process Tessera)
go test -tags integration ./internal/e2e/ -run "Transparency"
```

## Related Docs

| Doc | Topic |
|:--|:--|
| [ADRs](decisions/) | Architecture decisions |
| [ADR 0044: Remove PostgreSQL](decisions/remove-postgresql.md) | Why and how Postgres was removed |
| [API spec](api/openapi.yaml) | OpenAPI 3.1 definition |
| [SLRs](requirements/service-level-requirements.md) | Service level requirements |
