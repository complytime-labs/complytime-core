# AGENTS.md

Guide for AI coding agents working on complytime-core.

---

## Project Overview

complytime-core is an evidence locker system for compliance artifacts. Four components in one repo, connected by NATS.

### Binaries

- `cmd/gateway` — Evidence Gateway: HTTP API, JWT/OIDC auth, Cedar authz, receipt wrapping, async JetStream worker
- `cmd/locker` — Evidence Locker: multi-ledger Tessera WORM storage, internal only

### Package Structure

| Package | Owns |
|:--|:--|
| `gateway` | HTTP handlers, async worker, publisher trust (NATS KV), CloudEvents |
| `gateway/receipt` | Receipt wrapping (gemara-receipt/v1), DSSE channel receipt, unwrap helpers |
| `authz` | Cedar authorization middleware, embedded policies, route-to-action mapping |
| `locker` | Multi-ledger Tessera management, OpenAPI handlers, shared-secret auth, tlog-tiles |
| `nats` | NATS connection, JetStream stream/KV configs, subject constants |

### Key Patterns

- **OpenAPI first:** Specs in `api/`, generate Chi server interfaces with oapi-codegen
- **Cedar authorization:** Policies in `internal/authz/policies/`, schema validated in CI
- **Two receipt types:** `gemara-receipt/v1` (unsigned, content inline) and `gemara-dsse-channel-receipt/v1` (DSSE companion, content by-reference)
- **Flat slug subject IDs:** `[a-zA-Z0-9][a-zA-Z0-9_-]{0,253}` — no dots (NATS safe)
- **Tests:** `testify/require` + `testify/assert`, `httptest` for handlers, embedded NATS for integration

### ADRs

Architecture decisions in `adrs/`. Previous architecture decisions archived in `adrs/archive/`.

### Dependencies

- Go 1.25, Chi, cedar-go, jwtauth, in-toto/attestation, Tessera, NATS JetStream, CloudEvents SDK
