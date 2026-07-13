# SPDX-License-Identifier: Apache-2.0

# ADR 0026: ConnectRPC Internal API for complytime-mcp

**Status:** Superseded — `complytime-mcp` (gateway MCP facade) migrated to REST; ConnectRPC and internal port removed.

**Historical note:** (names reflect pre-extraction terminology in some narrative below.)

**Date:** 2026-05-13

## Context

complytime-mcp and the gateway both import `internal/postgres/` and hold
independent database connections to the same PostgreSQL instance. This
creates two problems:

1. **No API boundary.** complytime-mcp bypasses all gateway middleware —
   auth, write-protect, audit logging, rate limiting. A bug in
   complytime-mcp can write directly to production tables with no gate.

2. **Tight binary coupling.** Both binaries must be built and deployed
   from the same Go module at the same version. A schema migration
   change can silently break complytime-mcp at runtime if images drift
   during a rolling deploy.

complytime-mcp is the **only** non-gateway component that needs direct
data access. The UI uses REST; the workbench uses MCP via complytime-mcp.
The scope is one client, one server.

## Decision

Introduce a ConnectRPC internal API on the gateway's internal port
(:8081) and migrate complytime-mcp from direct SQL to a generated
ConnectRPC client.

### Why ConnectRPC over alternatives

| Option | Contract enforcement | Build complexity | Debug ergonomics |
|:--|:--|:--|:--|
| Internal REST + OpenAPI | Medium (spec drift test) | Low | High (curl) |
| **ConnectRPC** | **High (proto codegen)** | **Medium** | **High (curl + JSON fallback)** |
| Full gRPC | High (proto codegen) | High | Low (grpcurl only) |

ConnectRPC uses `.proto` files for schema definition and code
generation (same as gRPC), but the transport is standard HTTP — you
can `curl` endpoints with JSON bodies. This gives compile-time
contract enforcement without requiring gRPC-specific load balancer
configuration or debugging tools.

Single Go dependency: `connectrpc.com/connect`.

### Architecture

```
Agent ──MCP──► complytime-mcp ──ConnectRPC──► Gateway :8081 ──SQL──► PostgreSQL
```

complytime-mcp no longer holds a `*sql.DB` connection. PostgreSQL has one
writer (the gateway). The gateway enforces validation, audit logging,
and write-protect on every path — public and internal.

### Proto definition

A single `.proto` file defines the internal contract:

```
proto/studio/v1/studio.proto
```

Covers the resources and tools complytime-mcp currently exposes:

| Proto service method | Current complytime-mcp path |
|:--|:--|
| `ListPolicies` | `complytime://policies` |
| `GetPolicy` | `complytime://policies/{id}` |
| `QueryEvidence` | `complytime://evidence?policy_id=...` |
| `IngestEvidence` | `ingest_evidence` tool |
| `ListPosture` | `complytime://posture?policy_id=...` |
| `ListCatalogs` | `complytime://catalogs` |
| `ListMappings` | `complytime://mappings?source_catalog=...` |
| `ListAuditLogs` | `complytime://audit-logs` |
| `CreateDraftAuditLog` | `save_draft_audit_log` tool |
| `ListThreats` | `complytime://threats` |
| `ListRisks` | `complytime://risks` |

### Service layer refactor

Gateway handler logic is currently embedded in Echo handler functions.
To serve both REST and ConnectRPC, factor out a shared service layer:

```
Echo handler     ──┐
                   ├──► PolicyService.List() ──► internal/postgres/
Connect handler  ──┘
```

This is an incremental refactor — extract the core query/write logic
from each Echo handler into a service struct, then wire both Echo and
Connect handlers to the same service.

### Auth model for internal API

Network-enforced (Kubernetes NetworkPolicy restricts access to :8081).
No token or mTLS. Same model currently used for agent-to-gateway
traffic per `internal-endpoint-isolation.md` (ADR 0006).

### Where complytime-mcp lives

Stays in `complytime-core`. The `.proto` file, generated client, and
complytime-mcp binary are all in the same Go module. A schema migration,
internal API handler update, and complytime-mcp client update land in one
PR. Compile-time breakage if any side drifts.

## Consequences

**Positive:**
- `.proto` file **is** the data contract — field rename breaks both
  sides at compile time
- complytime-mcp drops `internal/postgres/` import and `*sql.DB` — no
  more direct database access from a second binary
- Gateway enforces middleware on all write paths (internal and public)
- If complytime-mcp ever moves to Python (`complytime-studio`), `protoc`
  generates a Python client from the same `.proto`
- Additive proto field evolution (field numbers) gives free forward
  compatibility

**Negative:**
- ~5-10ms added latency per MCP call (loopback HTTP) — negligible
  relative to LLM inference time
- New build dependency: `protoc` + `protoc-gen-go` +
  `protoc-gen-connect-go` (or `buf`)
- Service layer refactor touches all ~20 handler functions

**Neutral:**
- Internal API is not exposed publicly; Nginx only routes to :8080
- No impact on studio-ui, complytime-studio, or studio-deploy

## References

- ADR 0006: [Internal Endpoint Isolation](internal-endpoint-isolation.md)
- ADR 0025: [Data Platform + Workbench Split](data-platform-workbench-split.md)
- [ConnectRPC](https://connectrpc.com/)
