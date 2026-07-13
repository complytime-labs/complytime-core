# Internal Endpoint Isolation: Dual-Port Gateway

**Status:** Superseded — internal port removed; draft audit log endpoint moved to public API; `complytime-mcp` uses REST on `:8080`.

**(names reflect pre-extraction terminology where the narrative cites older Helm or layout names)**

**Date:** 2026-04-25

## Context

The gateway exposes `/internal/*` endpoints for agent-to-gateway communication (e.g., `POST /internal/draft-audit-logs`). These endpoints have no session/auth middleware. The current guard relies on `X-Forwarded-For` / `X-Real-Ip` header presence to distinguish "external" from "internal" traffic. If a client reaches the gateway without those headers (NodePort, port-forward, misconfigured LB), requests pass through unauthenticated.

The Helm `NetworkPolicy` comments reference a `REQUIRE_INTERNAL_HEADER` / `X-Internal-Source` mechanism that does not exist in the gateway code.

## Decision

Split the gateway into two listening ports within the same binary:

| Port | Purpose | Routes | Auth |
|:--|:--|:--|:--|
| `:8080` | Public (user-facing) | `/api/*`, `/auth/*`, `/healthz`, SPA | Session + admin guard |
| `:8081` | Internal (agent-only) | `/internal/*` | Network-isolated via NetworkPolicy |

### Helm Changes

- **Second Service:** `studio-gateway-internal` (ClusterIP, port 8081). No Ingress exposure.
- **NetworkPolicy:** New `studio-allow-gateway-internal` restricts port 8081 ingress to pods matching `app.kubernetes.io/component: assistant`.
- **Existing Service:** `studio-gateway` unchanged (port 8080).

### Gateway Changes

- Bind a second `http.Server` on `INTERNAL_PORT` (default `8081`).
- Register `/internal/*` routes only on the internal mux.
- Remove the `X-Forwarded-For` / `X-Real-Ip` heuristic from `writeProtect`.
- Public mux returns 404 for `/internal/*`.

### Agent Changes

- `agents/assistant/tools.py` `publish_audit_log` targets `studio-gateway-internal:8081` instead of `studio-gateway:8080`.

## Consequences

- `/internal/*` is unreachable from the public Service regardless of headers.
- L3/L4 NetworkPolicy enforces pod identity without L7 parsing.
- No new dependencies. Same binary, same container, same pod.

## Future: mTLS via Service Mesh

This is a stepping stone. When a service mesh (Istio, Linkerd) is adopted, the internal port can be further secured with mTLS for mutual pod identity verification. The dual-port pattern remains compatible — the mesh encrypts the transport, NetworkPolicy narrows the source.

## Rejected Alternatives

| Approach | Why Not |
|:--|:--|
| Shared secret header (`X-Internal-Token`) | Secrets in env vars, rotatable but not zero-trust. Acceptable as quick fix but doesn't match the "separate Service" intent. |
| Single port + Cilium L7 policy | CNI-specific. Not all clusters run Cilium. L3/L4 policy is universally supported. |
| mTLS now | Requires mesh operator deployment, cert management. Premature for current deployment targets. |
| Header heuristic (current) | Bypassable. Not a real security boundary. |
