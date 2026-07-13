# ADR 0031: Three-Protocol Serving Layer

**Status:** Accepted
**Date:** 2026-05-15

## Context

ComplyTime Studio is a compliance data platform. Clients include browser UIs, AI agents (Claude Desktop, Cursor, studio-assistant), dashboards (Grafana, Metabase), and CI/CD pipelines. Each client family has a natural protocol:

- **Browser / CI** — REST
- **AI agents / MCP hosts** — MCP
- **Dashboards / ad-hoc analysis** — SQL

The serving layer must support all three without forcing clients into a protocol mismatch.

## Decision

The gateway exposes three serving protocols:

| Protocol | Scope | Access | Target Clients |
|:---|:---|:---|:---|
| **REST** | Full CRUD — authoritative API | Read + write, gated by OAuth2 Proxy / RBAC | studio-ui, CI/CD, services |
| **MCP** | Complete evidence read surface + `save_draft_audit_log` | Read + draft write only | AI agents, MCP hosts |
| **SQL** | Read-only `studio_reader` role | SELECT only | Grafana, Metabase, ad-hoc |

### REST (unchanged)

The gateway REST API (`/api/*`) remains the authoritative contract. OpenAPI-documented, auth via OAuth2 Proxy. All mutations flow through REST.

### MCP (expanded)

`complytime-mcp` is a gateway facade — it proxies to REST via HTTP, it does not connect to Postgres directly. This preserves a single auth/validation layer.

**Resources (12 static + 4 templates):**
- Static: policies, catalogs, posture, audit-logs, draft-audit-logs, threats, risks, certifications, requirements, control-threats, risk-threats, inventory
- Templates: `policies/{id}`, `audit-logs/{id}`, `draft-audit-logs/{id}`, `requirements/{id}/evidence`

Programs are workbench-owned (see ADR #0036) and served via `studio-mcp`.

**Tools (2):**
- `query_evidence` — full filter set (policy, control, target, time range, pagination)
- `save_draft_audit_log` — the only write path for agents

No evidence ingest, no import, no CRUD mutations via MCP. Agents audit and post results.

### SQL (new)

A `studio_reader` Postgres role with `SELECT`-only grants on all tables. Created by migration `014_readonly_role.sql` and configured at deploy time via Helm values or Docker Compose init scripts.

Intended for dashboard tools that speak native Postgres wire protocol. The reader role has no write, DDL, or role-management capabilities.

## Consequences

- Agents cannot bypass the gateway for writes — all mutations are auditable via REST middleware.
- Dashboard clients get native SQL without a translation layer.
- MCP surface must be updated when new REST read endpoints are added.
- The `studio_reader` password must be rotated separately from the primary `studio` user.
- `complytime-mcp` stays thin — no Postgres client, no independent query logic.
