# Gemara MCP Session Initialization Failures

Status: **active workaround** (manual pod restart); **upstream fix needed** (gemara-mcp)

## Problem

Agent jobs fail with `Failed to create MCP session: unhandled errors in a TaskGroup (1 sub-exception)` when `studio-gemara-mcp` is unhealthy. The Google ADK's `McpSessionManager` has zero retry tolerance on session creation -- a single 500 from the MCP server kills the entire job.

## Root Cause

The `gemara-mcp` Go binary leaks OS threads over time. After ~24h and multiple restarts, the container hits the kernel PID limit:

```
runtime: may need to increase max user processes (ulimit -u)
fatal error: newosproc
```

`newosproc` means the Go runtime cannot create new OS threads via `clone(2)`. The container's process table is exhausted. When a request arrives during this state, the MCP server returns HTTP 500. The agent's ADK runtime receives the 500 during MCP session initialization (tool discovery), wraps it in `ConnectionError`, and abandons the job.

## Failure Chain

```
Agent receives A2A request
  → ADK creates MCP session to studio-gemara-mcp
    → POST http://studio-gemara-mcp.kagent:3000/mcp
      → 500 Internal Server Error (gemara-mcp out of threads)
        → ConnectionError: Failed to create MCP session
          → Job fails immediately, no retry
```

## Observed Behavior

- `studio-gemara-mcp` pod shows 6+ restarts over 24h
- Pod logs show `fatal error: newosproc` followed by stack trace in `runtime.newosproc` → `runtime.newm1` → `runtime.main`
- Subsequent requests after crash recovery succeed (200 OK), but the agent has already given up
- The MCPServer CRD reports `READY=True` because the pod eventually recovers

## Workaround

Restart the gemara-mcp pod when the error occurs:

```bash
kubectl rollout restart deployment studio-gemara-mcp -n kagent
```

## Upstream Issues

| Component | Issue | Description |
|---|---|---|
| **gemara-mcp** | TBD | Go binary leaks OS threads/goroutines, eventually hitting `newosproc`. Needs goroutine leak investigation. |
| **Google ADK** | Structural | `McpSessionManager.create_session` has no retry on transient HTTP errors (500, 503). A single failure during session init is terminal. |

## What We Cannot Fix From This Repo

- **Resource limits on MCPServer pods**: kagent manages the pod spec for MCPServer CRDs. Our Helm chart declares the MCPServer CR, but kagent's controller renders the Deployment. We cannot set `resources.limits` or `securityContext.pidsLimit` from the CR spec.
- **ADK retry behavior**: Session creation retry logic is internal to `google.adk.tools.mcp_tool.mcp_session_manager`. No configuration knob exists.

## Recommendations for Upstream

**gemara-mcp**:
- Profile goroutine count under sustained load (`runtime.NumGoroutine()`)
- Add a `/healthz` endpoint that checks goroutine count and returns 503 when approaching limits
- Investigate whether the streamable-http MCP transport leaks goroutines on client disconnect

**kagent MCPServer CRD**:
- Allow `resources` and `securityContext` fields on the MCPServer spec so operators can set PID limits and memory caps
