# ComplyTime Core

> **Note:** This project is built with AI assistance. Code, documentation, and design specs are authored collaboratively with LLM tools.

Data platform for automated compliance evidence ingestion, verification, and posture analytics. Built around the [OpenSSF Gemara](https://gemara.openssf.org/) project.

Core ingests evidence from scanning tools, stores it in an immutable [Tessera](https://github.com/transparency-dev/tessera) transparency log, certifies it for quality, and computes compliance posture across policies and targets. AI agents in the companion [Studio](https://github.com/complytime-labs/complytime-studio) workbench draft audit-ready artifacts from the stored evidence.

## What It Does

| Capability | What you get |
|:--|:--|
| **Evidence Ingestion** | Ingest Gemara artifacts via REST API with JWT authentication and async NATS processing |
| **Transparency Log** | Every submission is appended to a Tessera log — tamper-evident, immutable, cryptographically verifiable |
| **Evidence Certification** | Automated validation pipeline checks schema, provenance, and executor integrity |
| **Witness Verification** | Independent witness service verifies certification, publisher trust, and reference integrity |
| **Policy Enrollment** | Targets register with dimensional metadata; publishers discover applicable policies via dimension matching |
| **Posture Analytics** | See which requirements are covered, which have gaps, and where evidence is stale or missing |
| **Audit Preparation** | AI agents draft [Gemara AuditLog](https://gemara.openssf.org/) artifacts; humans review and promote to official records |

## ComplyTime Ecosystem

| Repository | Role | Language |
|:--|:--|:--|
| **complytime-core** (this repo) | Data platform — evidence storage, verification, posture, certification | Go |
| [complyctl](https://github.com/complytime/complyctl) | CLI — pulls policies from OCI, scans targets via provider plugins, produces evidence | Go |
| [complypack](https://github.com/complytime/complytime/issues/8) | Policy authoring — validate, test, package assessment logic as signed OCI artifacts | Go |
| [complytime-studio](https://github.com/complytime-labs/complytime-studio) | Audit workbench — AI agents, A2A routing, Gemara tools | Python |
| [studio-ui](https://github.com/complytime/studio-ui) | Analyst dashboard SPA + Nginx reverse-proxy | TypeScript |
| [studio-deploy](https://github.com/complytime/studio-deploy) | Helm chart + Docker Compose for local/cluster deployment | YAML |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | Compliance crosswalking — LLM-verified framework requirement mapping | Go |

**Shared contracts:** All tools produce and consume [Gemara](https://gemara.openssf.org/) YAML artifacts. Policies are distributed as signed OCI artifacts via container registries. No tool requires any other to function.

## Architecture

```
complyctl (scan targets)                    OCI Registry (policy bundles)
    │ evidence                                    │ import
    ▼                                             ▼
POST /api/ingest (JWT)                    POST /api/import (OCI pull)
    │                                             │
    ├─→ Tessera (append-only log, get log_index)  │
    ├─→ NATS core.ingest (async)                  │
    │       ↓                                     │
    │   IngestWorker                              │
    │       ├─→ PostgreSQL (queryable cache)       │
    │       ├─→ core.evidence.<policy_id>          │
    │       │       ↓                              │
    │       │   CertificationHandler               │
    │       │       ↓                              │
    │       │   evidence.certified = true/false    │
    │       ├─→ core.policy.new (broadcast)        │
    │       └─→ core.target.registered             │
    │                                              │
    └─→ 202 Accepted {job_id, log_index}           │
                                                   │
Witness (polls Tessera)                            │
    ├─→ Verify certification passed                │
    ├─→ Verify publisher trusted                   │
    ├─→ Verify reference integrity                 │
    ├─→ Advisory: check target registered          │
    └─→ Countersign checkpoint                     │
                                                   │
GET /api/policies/discover?target_id=X&timestamp=Y │
    └─→ Dimension matching + evaluation timeline   │
                                                   │
Studio agents ─→ GET /api/* (via MCP) ─→ draft audit logs
Studio UI ─→ posture dashboard, evidence explorer
```

### Binaries

| Binary | Command | Purpose |
|:--|:--|:--|
| **gateway** | `go build ./cmd/gateway` | HTTP API, evidence pipeline, certification, enrollment |
| **witness** | `go build ./cmd/witness` | Tessera verification daemon, checkpoint countersigning |

### Key Packages

| Package | Responsibility |
|:--|:--|
| `internal/store` | Business logic, HTTP handlers, domain interfaces |
| `internal/events` | NATS event bus (core.ingest, core.evidence, core.policy.new, core.target.registered) |
| `internal/tessera` | Transparency log client (Tessera — successor to Trillian) |
| `internal/certifier` | Evidence validation pipeline (schema, provenance, executor) |
| `internal/auth` | JWT verification with JWKS discovery, OAuth2 Proxy trust |
| `internal/postgres` | Connection pool, embedded migrations, schema management |

## Quick Start

### Prerequisites

| Tool | Purpose |
|:--|:--|
| `go` (>= 1.25) | Build gateway and witness |
| `docker` or `podman` | PostgreSQL + NATS containers |

### Run gateway locally

```bash
# Start dependencies
podman run -d --name pg -e POSTGRES_USER=complytime -e POSTGRES_PASSWORD=complytime -e POSTGRES_DB=complytime -p 5432:5432 docker.io/library/postgres:16
podman run -d --name nats -p 4222:4222 docker.io/library/nats:latest

# Build and run
export POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable"
export NATS_URL="nats://localhost:4222"
make gateway-build
./bin/studio-gateway
```

### Run tests

```bash
make test                    # Unit tests
make lint                    # Linter
make test-integration        # Integration tests (requires POSTGRES_TEST_URL)
./scripts/e2e-enrollment-test.sh  # E2E enrollment flow (starts containers automatically)
```

### Deploy (Kubernetes)

See [studio-deploy](https://github.com/complytime/studio-deploy) for Helm chart and Docker Compose orchestration.

## API Endpoints

| Method | Path | Purpose |
|:--|:--|:--|
| `POST` | `/api/ingest` | Submit Gemara YAML with JWT auth (async, returns log_index) |
| `GET` | `/api/ingest/jobs/:job_id` | Poll async ingest job status |
| `POST` | `/api/import` | Import OCI policy bundle (routes through Tessera) |
| `GET` | `/api/policies` | List all policies |
| `GET` | `/api/policies/:id` | Get policy with mappings |
| `GET` | `/api/policies/discover` | Discover applicable policies by target dimensions + timestamp |
| `GET` | `/api/targets` | List registered targets |
| `GET` | `/api/evidence` | Query evidence with filters |
| `GET` | `/api/posture` | Aggregated compliance gap analysis |
| `GET` | `/api/audit-logs` | List audit logs |
| `GET` | `/api/requirements` | Requirement coverage matrix |

## Development

| Target | Description |
|:--|:--|
| `make gateway-build` | Compile gateway to `bin/studio-gateway` |
| `make gateway-image` | Build gateway container image |
| `make test` | Run Go tests |
| `make test-integration` | Run integration tests (requires `POSTGRES_TEST_URL`) |
| `make lint` | Run golangci-lint |
| `make lint-openapi` | Check for API spec drift |

## Documentation

| Document | Purpose |
|:--|:--|
| [Architecture](docs/architecture.md) | Component boundaries, routing, communication |
| [Service Level Requirements](docs/requirements/service-level-requirements.md) | SLRs, ownership, gap analysis |
| [Decisions](docs/decisions/) | Architecture Decision Records |

## License

[Apache License 2.0](LICENSE)
