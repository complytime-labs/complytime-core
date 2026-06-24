# External Authorization Engine

**Status:** Superseded by [public-api-boundary.md](public-api-boundary.md)
**Date:** 2026-04-27

## Context

Studio uses a simple admin/reviewer RBAC model with two roles stored in ClickHouse. The `authorization-model.md` ADR describes a future RACI-scoped multi-tenancy model where access is per-policy, driven by Gemara Policy contacts and Google Groups membership.

External authorization engines (Zanzibar-based, policy-based, or identity-federation-based) could replace the hand-rolled role check when the authorization model grows beyond two roles.

## Decision

**Do not adopt an external authorization engine now.** The current 2-role model does not justify the operational overhead. Evaluate when RACI-scoped policy visibility is implemented.

**Update (2026-06-23):** Cedar authorization was adopted in the `public-api-boundary.md` decision. The project now uses AWS Cedar with a two-PEP model (public API + internal listener) and default-deny with forbid safety floors. This ADR is superseded.

## Rationale

**Current state (simple-authz):**
- 2 roles: `admin`, `reviewer`
- No resource scoping — all authenticated users see all policies
- Authorization is a single `if role == admin` check
- Any external engine would require: separate deployment, separate store, schema/policy authoring, SDK integration — disproportionate overhead for 2 roles

**Future state (RACI-scoped):**
- Per-policy access: "User A is *responsible* for Policy X but *informed* on Policy Y"
- Google Groups → RACI role resolution
- Resource-level scoping across policies, evidence, audit logs
- This is where an external engine earns its keep

## Trigger Conditions

Evaluate an external authorization engine when **any** of these occur:

1. RACI Phase 3 (`authorization-model.md`) implementation begins
2. More than 3 distinct authorization roles are needed
3. Resource-level scoping (per-policy, per-evidence) is required
4. Multiple teams share a Studio instance with different policy scopes

## Candidate Landscape

When triggered, evaluate candidates against project needs:

| Category | Examples | Strengths |
|:--|:--|:--|
| Zanzibar-based (ReBAC) | OpenFGA, SpiceDB, Authzed | Relationship tuples map to RACI contacts. Built-in audit trail. |
| Policy-based (ABAC/RBAC) | AWS Cedar, OPA/Rego, Cerbos | Rule engines, flexible policy language. Cedar has formal verification. |
| Identity federation | Keycloak, Zitadel | Full IdP with built-in RBAC/groups. Heavier footprint. |
| ClickHouse query (DIY) | `policy_contacts` table + gateway middleware | No new infra. Leverages existing stack. Harder to audit and test. |

Selection criteria: CNCF/OSS alignment, operational cost, consistency model, SDK maturity, Helm chart availability, and whether the engine's authorization model maps naturally to Gemara RACI semantics.

## Related

- [Authorization Model: RACI-Scoped Multi-Tenancy](authorization-model.md) — the target architecture
- [Default Admin & Token Hardening](default-admin-token-hardening.md) — current simple-authz
- [Public API Boundary](public-api-boundary.md) — the Cedar authorization model that supersedes this ADR
