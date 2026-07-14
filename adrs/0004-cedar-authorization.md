# ADR-0004: Cedar Authorization Middleware

## Status

Accepted

## Context

The evidence gateway needs fine-grained authorization: per-subject publisher trust, admin operations, and safety floors that cannot be overridden. We need an authorization engine that supports attribute-based access control (ABAC), embeddable policies, and a default-deny stance.

## Decision

### Cedar as the Authorization Engine

We use `cedar-policy/cedar-go` for authorization, implemented as reusable Chi HTTP middleware in `internal/authz/`.

### Entity Model

- **Principal:** `Publisher::{issuer}::{sub}` — consistent across all code paths (no email/sub inconsistency)
- **Actions:** `publish:artifact`, `admin:register-subject`, `admin:modify-trust`, `read:evidence`
- **Resource:** `Subject::{subject_id}` with attributes (e.g., `publisher_trusted: bool`)

### Middleware Behavior

The middleware extracts the principal from JWT context, maps the route to an action via a typed Go map (not string matching), builds the resource context (including publisher trust status from NATS KV), and calls `PolicySet.IsAuthorized()`. Deny returns 403.

Publisher trust lookup is fail-closed: if NATS KV is unavailable, the request is denied.

### Policy Design

- Default-deny: no permit rule = denied
- Forbid safety floors: `forbid` rules that cannot be overridden by any `permit`
- Policies embedded in the binary via `embed.FS`

### Schema Validation in CI

A `.cedarschema` file defines entity types, attributes, and valid actions. This schema is validated in CI using the `cedar validate` CLI command — catching typos, type mismatches, and undefined attributes at build time. The Go runtime does not load the schema; it trusts CI-validated policies.

### Route-to-Action Mapping

Routes map to Cedar actions via a typed map in `internal/authz/`. This centralizes the mapping, avoids string-matching bugs, and ensures unmapped routes get a clear denial.

## Consequences

- Cedar policies are embedded, not externally configurable — policy changes require a rebuild
- The `.cedarschema` adds a CI dependency on the Cedar CLI
- Publisher trust lookups add latency to every `publish:artifact` request (NATS KV is fast but not free)
- The middleware is reusable across gateway and any future service that needs Cedar authz
