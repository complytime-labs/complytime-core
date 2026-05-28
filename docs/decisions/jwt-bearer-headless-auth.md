# SPDX-License-Identifier: Apache-2.0

# ADR 0027: JWT Bearer Authentication for Headless API Access

**Status:** Accepted
**Date:** 2026-05-13

## Context

Studio's REST API on `:8080` supports two authentication paths:

1. **Browser sessions** — OAuth2 Proxy handles OIDC, injects
   `X-Forwarded-*` headers. Gateway reads headers, upserts user,
   enforces RBAC.

2. **`STUDIO_API_TOKEN`** — static shared secret for CI/seed scripts.
   Creates a fixed `api-token@internal` service account with a
   hardcoded write-scope allowlist.

Studio is a headless data platform. External services (CI pipelines,
partner integrations, other platforms) need authenticated API access
with per-identity RBAC. The static token fails this:

- **Single credential** — no per-service identity or audit trail.
- **No revocation granularity** — rotating the token disrupts all
  consumers simultaneously.
- **Hardcoded scope** — cannot grant different permissions to different
  services.
- **No user linkage** — bypasses the users table and RBAC entirely.

Agents reach the gateway via `complytime-mcp` (REST facade on `:8080`), so they stay on the primary listener — separate from the browser session cookie auth path this ADR extends.

## Decision

Enable OAuth2 Proxy's `--skip-jwt-bearer-tokens` flag. External
services authenticate by sending a JWT obtained from the same OIDC
provider as browser users.

### How it works

```
External Service
  └─ Client Credentials Grant → OIDC Provider → JWT
       └─ Authorization: Bearer <jwt>
            └─ OAuth2 Proxy (:4180)
                 ├─ Validates JWT signature against JWKS
                 ├─ Checks aud matches clientId (or extraAudiences)
                 ├─ Checks exp, iss claims
                 ├─ Extracts email, groups, preferred_username
                 └─ Injects X-Forwarded-* headers
                      └─ Gateway (:8080) — same path as browser sessions
                           ├─ UpsertUser (sub, issuer, email)
                           ├─ RBAC from users table
                           └─ Full middleware (write-protect, audit)
```

OAuth2 Proxy already has this capability. No gateway code changes.

### Why reuse OAuth2 Proxy over alternatives

| Option | Gateway changes | Token lifecycle | Identity linkage |
|:--|:--|:--|:--|
| **OAuth2 Proxy JWT** | **None** | **OIDC provider manages** | **Same users table** |
| Per-user API tokens in DB | New token CRUD, hash storage, middleware | Self-managed | Users table |
| Gateway JWT validation | JWKS fetch, signature verify, claim parsing | OIDC provider manages | Users table |
| mTLS client certificates | TLS config, cert management | PKI / cert-manager | New identity mapping |

OAuth2 Proxy JWT reuses 100% of existing infrastructure: the OIDC
provider issues and revokes tokens, the proxy validates them, the
gateway sees identical `X-Forwarded-*` headers regardless of whether
the caller is a browser or a service.

### Helm values

New fields under `auth.oauth2Proxy`:

| Field | Default | Purpose |
|:--|:--|:--|
| `skipJwtBearerTokens` | `false` | Accept JWT bearer tokens |
| `forceJsonErrors` | `false` | JSON 401/403 instead of HTML redirects |
| `bearerTokenLoginFallback` | `true` | On invalid JWT: redirect (`true`) or 403 (`false`) |
| `extraAudiences` | `[]` | Additional `aud` claims beyond `clientId` |
| `extraJwtIssuers` | `[]` | Additional trusted issuers (`issuer=audience`) |

Headless-only deployment:

```yaml
auth:
  oauth2Proxy:
    skipJwtBearerTokens: true
    forceJsonErrors: true
    bearerTokenLoginFallback: false
```

### STUDIO_API_TOKEN removal

The static `STUDIO_API_TOKEN` is removed entirely. It was a single
shared secret with a hardcoded service account identity
(`api-token@internal`) and a fixed write-scope allowlist. Every
problem it creates — no per-service identity, no revocation
granularity, no RBAC linkage — is solved by JWT bearer tokens.

| Deployment | Auth path |
|:--|:--|
| Production (proxy enabled) | JWT bearer via OAuth2 Proxy |
| Local dev (proxy disabled) | `X-Forwarded-*` header injection |
| CI seed (proxy disabled) | `X-Forwarded-Email` header (port-forward bypasses proxy) |
| CI seed (proxy enabled) | JWT bearer |

The gateway auth middleware no longer contains any static token
comparison, service account session type, or hardcoded write-scope
allowlist. The `ServiceAccount` field is removed from `Session`.
The `serviceAccountAllowedPaths` variable is removed. `RequireWrite`
enforces RBAC purely from the users table.

### User and role linkage

JWT bearer users follow the same identity lifecycle as browser users:

1. OAuth2 Proxy extracts `email` from JWT claims.
2. Gateway `ensureUser()` upserts into users table on first request.
3. New users get `reviewer` role (default).
4. If JWT `groups` claim contains `admin`, `BootstrapAdmin()` promotes
   automatically (same as browser path).
5. Admin promotes service identities via `PATCH /api/users/:email/role`.

Service identity emails (e.g. `ci-pipeline@myorg.iam.gserviceaccount.com`)
appear in the users table alongside human users, with their own role
and audit trail.

## Consequences

**Positive:**
- Zero gateway code changes — OAuth2 Proxy handles JWT validation
- Per-service identity — each service has its own OIDC client
  credentials and appears as a distinct user
- Standard RBAC — service identities get roles from the same users
  table as humans
- Token lifecycle delegated to OIDC provider — revocation, rotation,
  expiry are provider-managed
- Audit trail — every request is attributed to a specific email

**Negative:**
- Requires an OIDC provider that supports client credentials grant
  (most do: Keycloak, Okta, Azure AD, Google, Dex)
- Services must obtain a JWT before each session (or cache until
  expiry) — adds one HTTP call to the auth flow
- `extraAudiences` / `extraJwtIssuers` config adds surface area for
  misconfiguration

**Neutral:**
- No impact on agent path (complytime-mcp uses REST on `:8080`)
- No impact on studio-ui (browser sessions unchanged)
- `STUDIO_API_TOKEN` fully removed from gateway, Helm chart, and
  seed scripts

## Amendment (2026-05)

### Ingest Publisher-Attestation JWT

The `/api/ingest` endpoint now accepts a `publisher-attestation` JWT in the `Authorization` header. This JWT is not validated by OAuth2 Proxy — it is parsed by the gateway's own `JWTVerifier` to extract publisher identity (`iss`, `sub`) which is committed to the Tessera transparency log entry alongside the artifact YAML.

This is a separate concern from the headless auth path described above:

| Concern | ADR 0027 (original) | Ingest JWT (this amendment) |
|:--|:--|:--|
| Who validates | OAuth2 Proxy | Gateway `JWTVerifier` |
| Purpose | API authentication + RBAC | Publisher identity attestation |
| Scope | All `/api/*` routes | `/api/ingest` only |
| Identity flows to | users table (RBAC) | Tessera log + evidence table (provenance) |
| Algorithm restriction | Provider-dependent | ES256/RS256 family only (hardened) |
| Audience | OAuth2 Proxy `clientId` | Optional `JWT_AUDIENCE` env var |

The gateway-side JWT verification was added per the transparency ledger ADR to provide cryptographic publisher provenance. It coexists with OAuth2 Proxy — in production, OAuth2 Proxy authenticates the caller (establishing who can call the API), and the gateway's `JWTVerifier` attests publisher identity (establishing who is claiming responsibility for the artifact).

See: [Transparency Ledger ADR](transparency-ledger.md), [Witness Service ADR](witness-service.md)

## References

- ADR 0006: [Internal Endpoint Isolation](internal-endpoint-isolation.md)
- ADR 0007: [Default Admin & Token Hardening](default-admin-token-hardening.md)
- ADR 0026: [ConnectRPC Internal API](connectrpc-internal-api.md)
- [OAuth2 Proxy `--skip-jwt-bearer-tokens`](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview)
- Superseded ADR: [Authorization Model](authorization-model.md) — deferred
  RACI Phase 4 notes "API token scoping (per-tenant tokens)" as future work;
  this ADR addresses the per-service identity gap without full RACI scoping.
