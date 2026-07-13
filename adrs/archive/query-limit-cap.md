# Query Limit Cap

**Status:** Accepted
**Date:** 2026-04-25

## Context

`GET /api/evidence` accepts a `limit` query parameter with no upper bound. Default is 100 when omitted, but callers can pass arbitrarily large values. `GET /api/audit-logs` has no pagination at all. Both paths risk heavy ClickHouse reads and large JSON responses.

## Decision

Centralize a maximum query limit in `internal/consts` and silently clamp all list endpoints.

### Implementation

1. Add `MaxQueryLimit = 1000` to `internal/consts/consts.go`.
2. All list handlers (`/api/evidence`, `/api/audit-logs`, `/api/requirements`, etc.) clamp the requested `limit` to `min(requested, consts.MaxQueryLimit)`.
3. Endpoints without an explicit `limit` parameter default to `consts.DefaultQueryLimit` (100) and still respect the cap.
4. No 400 error — silently clamp. Callers get at most 1000 rows per request.

### Rationale

- Silent clamping avoids breaking existing callers that may not expect a 400.
- Single constant means one place to tune if operational needs change.
- Consistent behavior across all list endpoints.

## Consequences

- No API contract break. Callers requesting >1000 get 1000.
- ClickHouse query pressure bounded per request.
- Future pagination (cursor-based) can build on this cap.

## Rejected Alternatives

| Approach | Why Not |
|:--|:--|
| Return 400 if limit exceeded | Breaking change for callers. Requires documentation and client updates. |
| Per-endpoint limits | Inconsistent UX. Multiple constants to maintain. |
| No limit (status quo) | DoS risk via unbounded queries. |
