# PII in Structured Logs

**Status:** Accepted (revisit at RACI Phase 3)
**Date:** 2026-04-27

## Context

The gateway logs user emails via `slog` during OAuth login, role changes, bootstrap promotion, and error paths. These are structured key-value pairs (e.g., `"email", sess.Email`), not embedded in free-text. In the current single-tenant, admin-only-access-to-logs deployment, this is operationally useful and low risk.

## Decision

**Accept raw email logging for now.** Revisit when either condition triggers:

1. Multi-tenant RACI-scoped access lands (Phase 3 of `authorization-model.md`).
2. A compliance requirement (SOC 2, GDPR) mandates PII controls on log data.

## Affected Paths

| File | Log Site | Data |
|:--|:--|:--|
| `internal/auth/auth.go` | First admin promoted | `sess.Email` |
| `internal/auth/user_handlers.go` | Role change, bootstrap | `sess.Email`, `targetEmail` |
| `cmd/ingest/main.go` | Login fallback warning | `sess.Email` |

## Future Migration Path

When triggered, adopt **stable user IDs** (UUID) in the `users` table and log those instead:

| Step | Action |
|:--|:--|
| 1 | Add `user_id UUID` column to `users` table, backfill existing rows |
| 2 | Replace `slog` email fields with `"user_id", user.ID` |
| 3 | Optionally add `slog.Handler` wrapper that redacts any residual `email` keys |

## Alternatives Considered

| Approach | Rejected Because |
|:--|:--|
| Hash emails in logs (`sha256[:12]`) | Loses human readability for debugging; still correlatable |
| Structured redaction middleware now | Premature — adds complexity for a single-tenant deployment |
| Stop logging identity entirely | Breaks audit trail for role changes and bootstrap events |
