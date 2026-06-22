# AGENTS.md

Guide for AI coding agents working on complytime-core (ComplyTime Ingest).

---

## Project Overview

complytime-core is a Go service for compliance evidence ingestion and transparency. It uses the [Gemara](https://gemara.openssf.org/) schema for compliance artifacts, stores evidence in a [Tessera](https://github.com/transparency-dev/tessera) transparency log, and publishes events to NATS. No PostgreSQL.

### Binaries

- `cmd/ingest` — Ingest service: HTTP API, Tessera append, NATS publish, tlog-tiles API
- `cmd/monitor` — Content verification daemon: polls Tessera, validates entries
- `cmd/testjwks` — Test JWKS server for local development (not production)

### Package Structure

| Package | Owns |
|:--|:--|
| `evidence` | Evidence parsing, artifact type detection, publisher identity |
| `requirements` | Policy, catalog, control, target, trusted publisher types and interfaces |
| `certify` | Trust signal types and certification pipeline (to be moved to cmd/monitor) |
| `store` | Ingest HTTP handlers, route registration, ingest worker |
| `bus` | NATS event bus, JetStream durable consumer, NATS KV stores |
| `tessera` | Transparency log client (embedded library), signer key, tlog-tiles API |
| `auth` | JWT verification, JWKS discovery, OAuth2 Proxy session |
| `config` | Typed configuration from environment variables |
| `httputil` | HTTP middleware (CORS, security headers, rate limiting) |
| `gemara` | Gemara SDK wrappers for policy resolution and catalog import |

### Key Patterns

- **Interfaces in domain packages, implementations in `bus` (NATS KV) or `store`**: e.g., `requirements.TrustedPublisherStore` implemented by `bus.PublisherTrustKV`
- **Async ingest via NATS JetStream**: artifacts are Tessera-appended first, then processed asynchronously by `IngestWorker`
- **NATS KV for state**: publisher trust and target registry stored in NATS KV buckets, rebuildable from Tessera
- **Echo v4 HTTP framework**: routes registered in `internal/store/handlers.go`, middleware in `internal/httputil/`
- **Tessera embedded as Go library**: the ingest service IS the log personality, not a separate Tessera daemon

---

## Build and Test

```bash
go build ./cmd/ingest/          # Build ingest service
go build ./cmd/monitor/          # Build content monitor
go test -tags dev ./...          # Unit tests (no external deps)
go test -tags integration ./internal/e2e/ -run "Transparency"  # Integration tests
go vet ./...                     # Static analysis

# Smoke test (requires docker compose stack)
./scripts/setup-witness.sh
cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d
cd ../.. && ./scripts/smoke-test.sh
```

---

## Conventions

### Code Style

- Run `goimports` before committing
- Follow existing patterns in the package you're modifying
- No comments unless the WHY is non-obvious
- Domain types and interfaces live in their domain package, not in `store`
- Use library APIs instead of hand-rolled parsing/protocol code

### Git

- Sign commits: `git commit -S -s`
- Run `gitleaks detect --config ~/.gitleaks.toml --source . -v` before every commit
- Message format: `<type>: <subject>` (feat, fix, docs, test, refactor, chore, build, ci)
- Never commit secrets, API keys, tokens, or private catalog content

### Testing

Five layers — see [ADR 0045: Testing Strategy](docs/decisions/testing-strategy.md) for full details.

| Layer | What it answers | Location |
|:--|:--|:--|
| **Unit** | Does this function work? | `*_test.go` in package |
| **Contract** | Will downstream subscribers break? | `internal/bus/*_test.go` |
| **BDD E2E** | Does the full workflow work? | `internal/e2e/` (Ginkgo) |
| **Security evaluation** | Do the security properties hold? | `internal/e2e/` (Gemara + SARIF) |
| **Smoke** | Does the deployed stack work? | `scripts/smoke-test.sh` |

**Rules:**
- TDD: write tests before implementation
- Security claims require threat/control catalog entries + security evaluation test before implementation
- Every NATS event has a contract test
- Fail-closed behavior tested explicitly

### Error Handling

- Ingest worker uses three outcomes: `outcomeAck` (success), `outcomeNak` (transient, retry), `outcomeTerm` (permanent, no retry)
- Parse/validation errors are permanent (TERM); store errors are transient (NAK)
- Publisher trust lookup is fail-closed: reject if NATS KV unavailable

---

## Architecture Decisions

ADRs live in `docs/decisions/`. Read relevant ADRs before modifying a subsystem:

| ADR | Covers |
|:--|:--|
| `remove-postgresql.md` | Why Postgres was removed, NATS KV replacement, fail-closed auth |
| `transparency-ledger.md` | Tessera integration, embedded library, signer key |
| `anti-equivocation-witnessing.md` | Witness cosignatures, tlog-witness protocol |
| `content-verification-service.md` | Content verification, verification attestations |
| `public-api-boundary.md` | What's public vs authenticated |
| `jetstream-ingest-consumer.md` | NATS JetStream durable consumer design |
| `jwt-bearer-headless-auth.md` | JWT authentication model |

---

## Security

- Publisher authorization checked at ingest boundary via NATS KV allowlist (fail-closed)
- Trusted publishers are target-scoped OIDC identities managed via TargetRegistration
- JWT verification uses JWKS discovery with key rotation support
- Rate limiting on `/api/ingest` (per-IP token bucket)
- Witness cosignatures detect log equivocation (not prevent — see ADR)
- Tessera signer key stored with persistent file; ephemeral mode logs a warning
- Threat model: `internal/e2e/testdata/transparency-threats.yaml`
- Control catalog: `internal/e2e/testdata/transparency-controls.yaml`

---

## Upstream Dependencies

| Dependency | What it provides |
|:--|:--|
| [Gemara](https://github.com/gemaraproj/gemara) | Compliance schema (CUE definitions) |
| [go-gemara](https://github.com/gemaraproj/go-gemara) | Go SDK for parsing Gemara artifacts |
| [Tessera](https://github.com/transparency-dev/tessera) | Append-only transparency log (embedded library) |
| [transparency-dev/witness](https://github.com/transparency-dev/witness) | Omniwitness for checkpoint cosigning |

When upstream schema changes (e.g., Gemara ADRs), check whether complytime-core's parsers and types need updating. The `internal/gemara/` package wraps the SDK.
