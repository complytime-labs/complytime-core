<!-- SPDX-License-Identifier: Apache-2.0 -->

# ComplyTime Core Architecture

Compliance evidence locker with cryptographic guarantees. Four components in one repo, connected by NATS.

## System Overview

```
┌──────────────┐     JetStream      ┌──────────────┐
│   Gateway    │ ──────────────────► │    Locker    │
│   :8080      │                    │    :8081     │
│              │ ◄────── index ──── │              │
└──────┬───────┘                    └──────────────┘
       │                                   ▲
       │  CloudEvent                       │ tlog-tiles
       ▼                                   │
┌──────────────┐                    ┌──────────────┐
│   Thin DB    │                    │   Witness    │
│   (Plan 3)   │                    │  (external)  │
└──────────────┘                    └──────────────┘
```

| Component | Role | Tech |
|:--|:--|:--|
| **Evidence Gateway** (:8080) | Authenticates publishers, evaluates Cedar policies, wraps artifacts into receipts, enqueues to JetStream | Go, Chi, cedar-go, jwtauth, in-toto/attestation |
| **Evidence Locker** (:8081) | WORM storage — one Tessera transparency log per subject. Seals receipts, serves tlog-tiles | Go, Chi, Tessera (embedded), POSIX storage |
| **Thin DB** (:8082) | Read-only property graph materialized from NATS events | Plan 3 — Memgraph experimental, CrossCodex (PostgreSQL + Apache AGE) for production |
| **NATS** | JetStream for reliable delivery and replay. KV buckets for publisher trust and subject registry | NATS 2.14+ |

**Upstream tools** (produce artifacts consumed by the gateway):

| Tool | Role | Repository |
|:--|:--|:--|
| **complyctl** | CLI: pulls policies from OCI, scans targets, produces Gemara artifacts | [complyctl](https://github.com/complytime/complyctl) |
| **CrossCodex** | Query and analysis: evidence queries, coverage, framework crosswalking | [crosscodex](https://github.com/complytime-labs/crosscodex) |

## Binaries

### Evidence Gateway (`cmd/gateway`)

Public-facing service. Controls what enters the locker.

| Concern | Implementation |
|:--|:--|
| HTTP | Chi — OpenAPI-first with oapi-codegen |
| Authentication | JWT/OIDC via go-chi/jwtauth with JWKS discovery |
| Authorization | Cedar policies — default-deny middleware with forbid safety floors |
| Receipt wrapping | in-toto v1 Statements with JCS canonicalization (RFC 8785) |
| Async ingest | JetStream durable consumer — seal to locker, publish CloudEvent |
| Publisher trust | NATS KV bucket `publisher-trust` (fail-closed) |
| Subject registry | NATS KV bucket `subjects-registry` |

### Evidence Locker (`cmd/locker`)

Internal WORM storage. Not exposed to the public network.

| Concern | Implementation |
|:--|:--|
| HTTP | Chi — OpenAPI-first, shared-secret auth |
| Transparency log | Tessera — embedded Go library, POSIX storage, Ed25519 checkpoint signing |
| Multi-ledger | One Tessera Merkle tree per subject |
| tlog-tiles | `/checkpoint`, `/tile/*` per ledger for external verifiers |

## Authentication and Authorization

| Layer | Mechanism |
|:--|:--|
| **JWT/OIDC** | Gateway verifies bearer tokens via JWKS discovery. `JWT_AUDIENCE` required (fail-closed at startup). |
| **Cedar middleware** | Default-deny. Route-to-action typed map. Unmapped routes return 403. |
| **Publisher trust** | Per-subject allowlist in NATS KV. Fail-closed: reject if KV unavailable. |
| **Forbid safety floors** | Untrusted publishers blocked by `forbid/unless` rule — no permit can override. |
| **Locker auth** | Shared-secret `Authorization: Bearer` header. `/healthz` unauthenticated. |

## Data Flow

### Ingest (async, two-step)

**Step 1 — Gateway HTTP handler (synchronous):**
1. Receive `POST /api/ingest` with JWT bearer token + `X-Subject-ID` header
2. JWT/OIDC authentication, Cedar authorization (checks publisher trust for subject)
3. Wrap artifact in in-toto v1 receipt (or prepare DSSE + channel receipt)
4. Enqueue `IngestRef` to JetStream `INGEST` stream
5. Return `202 Accepted {job_id}`

**Step 2 — Gateway async worker (JetStream consumer):**
1. Pick `IngestRef` from durable consumer
2. Call locker `POST /ledgers/{subjectId}/seal` → log index
3. Publish CloudEvent to `core.evidence.{subjectId}`
4. Ack. Retry on transient failure, dead-letter on permanent.

### Two Receipt Formats (ADR-0003)

- **Unsigned artifacts:** Single entry — `gemara-receipt/v1` in-toto Statement wraps content inline
- **DSSE-signed artifacts:** Two entries — DSSE envelope stored byte-exact + `gemara-dsse-channel-receipt/v1` references it by digest

## API Surface

### Gateway (:8080)

| Method | Path | Purpose |
|:--|:--|:--|
| `POST` | `/api/ingest` | Submit artifact (async, returns 202) |
| `POST` | `/api/admin/subjects` | Register subject with trusted publishers (sync) |
| `GET` | `/api/ingest/jobs/{jobId}` | Poll job status |
| `GET` | `/healthz` | Health check (unauthenticated) |

### Locker (:8081, internal only)

| Method | Path | Purpose |
|:--|:--|:--|
| `POST` | `/ledgers` | Create ledger for a subject |
| `GET` | `/ledgers` | List all ledgers |
| `POST` | `/ledgers/{subjectId}/seal` | Seal receipt into ledger |
| `GET` | `/ledgers/{subjectId}/entry/{index}` | Fetch sealed receipt |
| `GET` | `/ledgers/{subjectId}/verify/{digest}` | Verify receipt by digest |
| `GET` | `/ledgers/{subjectId}/checkpoint` | Cosigned checkpoint |
| `GET` | `/ledgers/{subjectId}/tile/{level}/{index}/{width}` | Merkle tree tiles |

## NATS

### Subjects

| Subject | Use |
|:--|:--|
| `core.ingest` | Async ingest worker (JetStream durable consumer) |
| `core.evidence.{subjectId}` | Evidence sealed for a subject |
| `core.subject.registered` | Subject registered |
| `core.mapping.imported` | MappingDocument ingested |

### KV Buckets

| Bucket | Key | Value | Purpose |
|:--|:--|:--|:--|
| `publisher-trust` | `subjects.{subjectId}` | JSON array of `[{issuer, sub}]` | Authorization at ingest boundary |
| `subjects-registry` | `{subjectId}` | JSON registration marker | Subject metadata |

Both are materialized views. Rebuildable from the locker if lost.

## Configuration

| Variable | Required | Purpose |
|:--|:--|:--|
| `NATS_URL` | Yes | NATS connection URL |
| `LOCKER_URL` | Yes (gateway) | Internal locker HTTP URL |
| `LOCKER_SECRET` | Yes | Shared secret for gateway→locker auth |
| `JWT_ISSUERS` | Yes (gateway) | Comma-separated OIDC issuer URLs |
| `JWT_AUDIENCE` | Yes (gateway) | Expected JWT audience (fail-closed) |
| `GATEWAY_LISTEN_ADDR` | No | Gateway listen address (default: `:8080`) |
| `LOCKER_DATA_PATH` | No | Locker storage directory (default: `/data/ledgers`) |
| `LOCKER_LISTEN_ADDR` | No | Locker listen address (default: `:8081`) |

## Testing

```bash
# Unit tests
go test ./... -v -count=1

# Integration tests (full lifecycle: register → ingest → seal → verify)
go test ./internal/gateway/ -tags integration -v

# Build
make build

# Docker Compose
docker compose -f deploy/compose/docker-compose.yaml up --build
```

## Related

| Doc | Topic |
|:--|:--|
| [ADRs](../adrs/) | Architecture decisions |
| [ADR-0003](../adrs/0003-receipt-model.md) | Receipt model (in-toto + JCS + two-entry DSSE) |
| [ADR-0004](../adrs/0004-cedar-authorization.md) | Cedar authorization middleware |
| [Gateway OpenAPI](../api/gateway/openapi.yaml) | Gateway API spec |
| [Locker OpenAPI](../api/locker/openapi.yaml) | Locker API spec |
