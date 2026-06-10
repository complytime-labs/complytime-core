# Modulith Architecture with Domain Packages

## Status

Accepted

## Context

complytime-core started as a single `store` package containing HTTP handlers, DB queries, domain types, business logic, and coordination code (42 files, 160 functions, 16 interfaces). As the codebase grew, this created coupling problems — `store` imported `events` for message types, and `events` duplicated `store` types to avoid import cycles.

The system is already distributed at the edges: the gateway serves the REST API, complytime-studio is a separate UI, and the witness service runs independently. The core backend is a single Go binary (modulith) where domain boundaries are enforced by the Go compiler rather than network APIs.

## Decision

Organize `internal/` into domain-oriented packages where each major functionality area owns its types and interfaces as leaf packages. The `store` package becomes a thin implementation hub backed by `pgxpool.Pool`. HTTP handlers live in `api/`.

### Package structure

```
internal/
  evidence/       # evidence types, flatten logic, validation
  requirements/   # policies, catalogs, controls, threats, risks, mappings, targets
  certify/        # certification pipeline, trust signals
  audit/          # audit logs, drafts, evidence assessments
  posture/        # requirement matrix, inventory
  db/             # postgres pool, migrations
  bus/            # NATS pub/sub
  auth/           # user sessions, RBAC
  api/            # HTTP handlers
  store/          # Store struct, DB methods, IngestWorker, coordination
  ingest/         # NATS message envelope types (IngestRef, IngestStreamConfig)
```

### Dependency direction

```
api → store → {evidence, requirements, certify, audit, posture, ingest}
bus → {ingest, certify}
Domain packages → (nothing internal — they are leaves)
```

The Go compiler enforces this: if a domain package imports `store` or `api`, the build fails with an import cycle.

### Boundary enforcement

- **Between deployed services** (gateway, witness, studio): network APIs
- **Within the modulith**: Go compiler import direction + interface satisfaction checks
- **If splitting further**: NATS is already the seam — the ingest worker and certifier are NATS consumers wired in-process today

## Future service split points

The modulith is designed so these can become independent binaries without proto or schema migration:

| Service | Current location | Split trigger | Transport |
|:--|:--|:--|:--|
| **Gateway** | `cmd/gateway` | Already separate | HTTP |
| **Ingest Worker** | `store/ingest_worker.go` | Need to scale YAML parsing independently | NATS JetStream (already wired) |
| **Certifier** | `certify/handler.go` | Need to scale certification independently | NATS evidence events (already wired) |
| **Witness** | `cmd/witness` | Already separate | PostgreSQL + Tessera |

Splitting requires: new `cmd/` binary, import the same domain packages, connect to the same NATS stream. No proto or API contract changes needed because the message types live in domain packages shared by all binaries.

## Consequences

- New features go in the appropriate domain package, not in `store`
- Adding a new domain (e.g., `publish/` for trusted publishing) is a new leaf package
- The `store` package grows only when new DB tables are needed, not when new business logic is added
- Proto is not needed unless we add a non-Go service or need cross-language contracts
