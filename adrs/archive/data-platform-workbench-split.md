<!-- SPDX-License-Identifier: Apache-2.0 -->

# Data Platform + Studio Workbench Split

**Status:** Accepted
**Date:** 2026-05-13
**Supersedes:** [Three-component architecture (monorepo)](three-component-architecture.md)

## Context

The Go gateway served two distinct roles through a single binary:

1. **Data platform** — evidence storage, certifier pipeline, posture computation, content ingestion, policy/catalog CRUD.
2. **Integration glue** — A2A proxy to agents, agent directory, chat state, Gemara MCP proxy (validate/migrate), OCI registry browse, artifact publish.

This coupling meant the data platform could not scale, deploy, or evolve independently from agent-support concerns. External consumers that only need evidence and posture data inherit A2A routing, MCP proxy logic, and agent lifecycle management.

The SPA extraction (ADR #0022) moved the UI out. This decision completes the separation by extracting agent-support concerns into their own process.

## Decision

Split the gateway into two deployable services:

1. **Data Platform** (`complytime-core`) — Go gateway serving `/api/*`. Owns PostgreSQL-backed CRUD, the certifier pipeline (in-process via NATS), posture reads, content ingestion from registries, and user auth.

2. **Studio Workbench** (`complytime-studio`) — Python server (Starlette) serving `/workbench/*`. Owns A2A routing to LangGraph agents, agent directory, chat state, Gemara validate/migrate (direct MCP), OCI publish and registry browse (direct MCP).

The **Studio UI** (`studio-ui`) Nginx routes requests to the correct backend:

```
/api/*              → data-platform:8080
/auth/*, /oauth2/*  → data-platform:8080
/workbench/*        → studio-workbench:8090
```

## Packages Extracted from Gateway

| Package | Responsibility | New Home |
|:--|:--|:--|
| `internal/agents` | A2A proxy, agent directory | studio-workbench |
| `internal/proxy` | Gemara MCP JSON-RPC proxy | studio-workbench |
| `internal/registry` | OCI repository/tag/manifest browse | studio-workbench |
| `internal/publish` | YAML bundle assembly + OCI push | studio-workbench |
| Chat handlers (`internal/auth`) | Conversation history GET/PUT | studio-workbench |

## Consequences

| Topic | Effect |
|:--|:--|
| Data platform identity | Gateway is a pure data API. No agent, MCP, or OCI concerns. |
| Workbench colocates with agents | Agent-support endpoints run in the same process as agents. Direct MCP connections replace HTTP proxying through Go. |
| Nginx routing | Two upstreams instead of one. Path-based split at the reverse proxy. |
| Independent scaling | Data platform scales on query load. Workbench scales on agent concurrency. |
| CORS | Eliminated. Both backends are same-origin behind Nginx. |
| Agent lifecycle | Workbench owns agent discovery and A2A routing. Data platform has no agent awareness. |

## Related

- [Studio SPA extraction](studio-spa-extraction.md)
- [Modulith gateway architecture](backend-architecture.md) (historical context)
- `docs/requirements/service-level-requirements.md` — SLRs that drove the split
