# Default Admin & Token Hardening

**Status:** Accepted
**Date:** 2026-04-25

## Context

`studio-deploy/charts/complytime/values.yaml` ships two dev-friendly defaults that become production liabilities:

1. `auth.admins: []` — empty list means **all authenticated users are admins**.
2. `auth.apiToken: "studio-dev-token"` — predictable token grants full API write as `api-token@internal`.

Both are fine for local development. Both are silent security holes in production if left unchanged.

## Decision

**Warn-loudly at startup.** No hard failure.

### Gateway Startup Behavior

| Condition | Action |
|:--|:--|
| `ADMIN_EMAILS` is empty | Log `slog.Warn("ADMIN_EMAILS is empty — all authenticated users have admin access")` on startup |
| `STUDIO_API_TOKEN` equals `"studio-dev-token"` | Log `slog.Warn("STUDIO_API_TOKEN is the default dev value — rotate before production use")` on startup |

### Helm `NOTES.txt`

Add a production checklist section warning operators to set `auth.admins` and rotate `auth.apiToken`.

### Values Documentation

Add inline comments in `values.yaml` marking both fields as "MUST override for production."

## Consequences

- Dev workflow unchanged — no startup failures.
- Prod deployments surface warnings in pod logs, visible in any log aggregator.
- Operators who read `helm install` output see the checklist.

## Rejected Alternatives

| Approach | Why Not |
|:--|:--|
| Fail-closed (refuse to start) | Breaks `kind` / local dev without explicit config. Onboarding friction. |
| Read-only mode when admins empty | Confusing UX — user authenticates but can't write, with no clear reason. |
| Document-only | Relies on human attention. Easy to miss in a CI/CD pipeline. |
