# ComplyTime Core

Compliance evidence locker with cryptographic guarantees. Submit assessment artifacts, get tamper-evident, verifiable records.

> **Status:** Active development — evidence gateway and locker services implemented ([#128](https://github.com/complytime-labs/complytime-core/issues/128)). Thin DB (Plan 3) and production infrastructure (Plan 4) are next.
>
> **Built with AI:** Code, documentation, architecture decisions, and design specs are authored collaboratively with LLM tools. PRs are labeled `llm-assisted`.

## Architecture

Two microservices in one repo:

```
┌──────────────┐     JetStream      ┌──────────────┐
│   Gateway    │ ──────────────────► │    Locker    │
│   :8080      │     (receipts)     │    :8081     │
│              │                    │              │
└──────────────┘                    └──────────────┘
       │               NATS KV             │
       │          (job status, trust)       │
       │  CloudEvent                       │ tlog-tiles
       ▼                                   ▼
┌──────────────┐                    ┌──────────────┐
│   Thin DB    │                    │   Witness    │
│   (planned)  │                    │  (external)  │
└──────────────┘                    └──────────────┘
```

- **Evidence Gateway** (:8080) — Gemara-speaking evidence collector. Authenticates publishers (JWT/OIDC), evaluates Cedar authorization policies, validates artifacts against Gemara JSON Schemas, wraps into in-toto v1 receipts, publishes to NATS JetStream.
- **Evidence Locker** (:8081) — content-agnostic trust store. Subscribes to NATS, seals receipt bytes into Tessera transparency logs (one per subject), serves tlog-tiles for external verifiers. Admin API for subject registration and publisher trust management.
- **NATS** — JetStream for reliable evidence delivery. KV buckets for job status, publisher trust, and subject registry.

## How It Works

```text
Admin (setup)
    │
    ▼
POST /admin/subjects → Locker :8081
    │  Create ledger, set trusted publishers
    │
Publisher (scanner, CI pipeline)
    │ Gemara artifact + JWT bearer token
    ▼
POST /api/ingest → Gateway :8080
    │
    ├── JWT/OIDC authentication
    ├── Cedar authorization (per-subject publisher trust)
    ├── Validate against Gemara JSON Schema (422 if invalid)
    ├── Wrap in in-toto v1 receipt (publisher identity + timestamp)
    ├── Write job status (pending) to NATS KV
    ├── Publish receipt bytes to JetStream
    │       ↓
    │   Locker subscribes → seal to Tessera → update job status (sealed)
    │
    └── 202 Accepted {job_id}
         ↓
    GET /api/ingest/jobs/{job_id} → pending | sealed | failed
```

Built around the [OpenSSF Gemara](https://gemara.openssf.org/) compliance schema.

## Quick Start

```bash
# Build
make build

# Run tests
make test

# Run with Docker Compose
docker compose -f deploy/compose/docker-compose.yaml up
```

## ComplyTime Ecosystem

| Repository | What it does |
| :-- | :-- |
| **complytime-core** (this repo) | Evidence locker — ingest, seal, verify |
| [complyctl](https://github.com/complytime/complyctl) | CLI — scan targets, produce evidence, pull policies from OCI |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | Framework crosswalking — map requirements across standards |

## Learn More

- [Architecture Decision Records](adrs/) — why things are the way they are
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## License

[Apache License 2.0](LICENSE)
