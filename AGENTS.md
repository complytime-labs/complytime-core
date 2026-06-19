# AGENTS.md

Guide for AI coding agents working on complytime-core.

---

## Project Overview

complytime-core is a Go data platform for compliance evidence ingestion, verification, and posture analytics. It uses the [Gemara](https://gemara.openssf.org/) schema for compliance artifacts and stores evidence in a [Tessera](https://github.com/transparency-dev/tessera) transparency log.

### Binaries

- `cmd/gateway` — HTTP API server, evidence pipeline, certification
- `cmd/monitor` — Tessera content verification daemon

### Package Structure

Domain-oriented packages under `internal/`:

| Package | Owns |
|:--|:--|
| `evidence` | Evidence parsing, flattening, publisher authorization, types |
| `audit` | Audit log types, draft promotion, reviewer edits |
| `requirements` | Policy, catalog, control, target, trusted publisher types and interfaces |
| `certify` | Trust signal types and certification pipeline |
| `store` | HTTP handlers, route registration, PostgreSQL store implementations |
| `bus` | NATS event bus, JetStream durable consumer |
| `tessera` | Transparency log client, signer key management |
| `auth` | JWT verification, JWKS discovery |
| `config` | Typed configuration from environment variables |
| `httputil` | HTTP middleware (CORS, security headers, rate limiting) |
| `posture` | Posture analytics, requirement coverage |
| `gemara` | Gemara SDK wrappers for policy resolution and catalog import |
| `db` | Connection pool, embedded migrations |

### Key Patterns

- **Interfaces in domain packages, implementations in `store`**: e.g., `evidence.EvidenceStore` is defined in `internal/evidence/interfaces.go`, implemented in `internal/store/store_evidence.go`
- **Async ingest via NATS JetStream**: artifacts are Tessera-appended first, then processed asynchronously by `IngestWorker`
- **Squirrel query builder**: all SQL uses `github.com/Masterminds/squirrel` with `sq.Dollar` placeholder format
- **Echo v4 HTTP framework**: routes registered in `internal/store/handlers.go`, middleware in `internal/httputil/`

---

## Build and Test

```bash
make gateway-build           # Build gateway binary
go build ./...               # Verify compilation
go test ./...                # Unit tests (no database required)
go test -tags integration    # Integration tests (requires POSTGRES_TEST_URL)
go vet ./...                 # Static analysis
make lint                    # golangci-lint
```

---

## Conventions

### Code Style

- Run `goimports` before committing
- Follow existing patterns in the package you're modifying
- No comments unless the WHY is non-obvious
- Domain types and interfaces live in their domain package, not in `store`

### Git

- Sign commits: `git commit -S -s`
- Run `gitleaks detect --config ~/.gitleaks.toml --source . -v` before every commit
- Message format: `<type>: <subject>` (feat, fix, docs, test, refactor, chore, build, ci)
- Never commit secrets, API keys, tokens, or private catalog content

### Testing

- Unit tests: same package, `_test.go` suffix, no build tags
- Integration tests: `//go:build integration` tag, require `POSTGRES_TEST_URL`
- E2E tests: `internal/e2e/` with test data in `internal/e2e/testdata/`
- Use `testing` package and `httptest` for HTTP handler tests — follow patterns in `internal/httputil/*_test.go`

### Database Migrations

- Sequential numbered files in `internal/db/migrations/` (e.g., `034_feature_name.sql`)
- Embedded via `//go:embed migrations/*.sql` in `internal/db/client.go`
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency
- Add `//nolint:gosec` with explanation for known-safe uint64-to-int64 conversions on Tessera log indices

### Error Handling

- Use `internal/store/errors.go` sentinel errors and `ClassifyPgError` for PostgreSQL errors
- Ingest worker uses three outcomes: `outcomeAck` (success), `outcomeNak` (transient, retry), `outcomeTerm` (permanent, no retry)
- Parse/validation errors are permanent (TERM); store errors are transient (NAK)

---

## Architecture Decisions

ADRs live in `docs/decisions/`. Read relevant ADRs before modifying a subsystem:

| ADR | Covers |
|:--|:--|
| `transparency-ledger.md` | Tessera integration, signer key persistence |
| `content-verification-service.md` | Content verification, publisher trust |
| `anti-equivocation-witnessing.md` | Witness cosignatures, tlog-witness protocol |
| `trust-signals-certification.md` | Trust signal layers, certification pipeline |
| `modulith-domain-packages.md` | Package structure rationale |
| `jetstream-ingest-consumer.md` | NATS JetStream durable consumer design |
| `jwt-bearer-headless-auth.md` | JWT authentication model |
| `policy-enrollment.md` | Dimensional policy matching |

---

## Security

- Publisher authorization is enforced at evidence ingest time — unauthorized publishers are rejected
- Trusted publishers are target-scoped OIDC identities managed via TargetRegistration
- JWT verification uses JWKS discovery with key rotation support
- Rate limiting on `/api/ingest` (per-IP token bucket)
- Tessera signer key stored with 0600 permissions; ephemeral mode logs a warning
- Never log private key material; verifier (public) keys may be logged at debug level

---

## Upstream Dependencies

| Dependency | What it provides |
|:--|:--|
| [Gemara](https://github.com/gemaraproj/gemara) | Compliance schema (CUE definitions) |
| [go-gemara](https://github.com/gemaraproj/go-gemara) | Go SDK for parsing Gemara artifacts |
| [Tessera](https://github.com/transparency-dev/tessera) | Append-only transparency log |

When upstream schema changes (e.g., Gemara ADRs), check whether complytime-core's parsers and types need updating. The `internal/gemara/` package wraps the SDK.
