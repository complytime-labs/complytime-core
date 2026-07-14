# ComplyTime Core

Compliance evidence locker with cryptographic guarantees. Submit assessment artifacts, get tamper-evident, verifiable records.

> **Status:** Active development — evidence gateway and locker services implemented ([#128](https://github.com/complytime-labs/complytime-core/issues/128)). Thin DB (Plan 3) and production infrastructure (Plan 4) are next.
>
> **Built with AI:** Code, documentation, architecture decisions, and design specs are authored collaboratively with LLM tools. PRs are labeled `llm-assisted`.

## Architecture

Four components in one repo:

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

- **Evidence Gateway** (:8080) — authenticates publishers (JWT/OIDC), evaluates Cedar authorization policies, wraps artifacts into in-toto v1 receipts, seals them into the locker via async JetStream workers.
- **Evidence Locker** (:8081) — WORM storage. One Tessera transparency log per subject. Seals receipts, serves tlog-tiles for external verifiers. Internal only.
- **Thin DB** (Plan 3) — read-only property graph materialized from NATS events. Memgraph for experimental; CrossCodex (PostgreSQL + Apache AGE) for production.
- **NATS** — JetStream for reliable delivery and replay. KV buckets for publisher trust and subject registry.

## How It Works

```text
Publisher (scanner, CI pipeline)
    │ Gemara artifact + JWT bearer token
    ▼
POST /api/ingest (X-Subject-ID header)
    │
    ├── JWT/OIDC authentication
    ├── Cedar authorization (per-subject publisher trust)
    ├── Wrap in in-toto v1 receipt (provenance binding)
    ├── Enqueue to JetStream
    │       ↓
    │   Async worker → seal into locker → CloudEvent
    │
    └── 202 Accepted {job_id}
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
