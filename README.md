# ComplyTime Core

Compliance evidence pipeline with cryptographic guarantees. Submit assessment results, get verifiable posture.

> **Status:** Active redesign — this repo is being restructured from a monolithic pipeline to a focused ingestion and trust boundary service ([#128](https://github.com/complytime-labs/complytime-core/issues/128)). APIs, schema, and project scope are changing. Expect volatility.
>
> **Built with AI:** Code, documentation, architecture decisions, and design specs are authored collaboratively with LLM tools (Claude Code, Cursor). PRs are labeled `llm-assisted`.

## Why

Proving your systems are compliant means collecting evidence from scanners, CI pipelines, and manual reviews — then assembling it into something an auditor can verify. Today that evidence is scattered across tools, unverifiable after the fact, and manually stitched together at audit time.

ComplyTime Core is the backend that fixes this:

- **Every piece of evidence is Tessera-anchored** — appended to a tamper-evident transparency log before anything else happens. You can prove what was submitted, when, and that it hasn't changed.
- **Publisher identity is cryptographically verified** — JWT-authenticated OIDC identities tied to targets. A CI pipeline can only submit evidence for infrastructure it's authorized to assess.
- **Posture is queryable, not assembled** — compliance gaps, coverage, and staleness are computed from stored evidence in real time. No spreadsheets.
- **Audit artifacts are machine-generated, human-approved** — AI agents draft audit logs from evidence; humans review and promote them to official records.

Built around the [OpenSSF Gemara](https://gemara.openssf.org/) compliance schema. All artifacts in, all artifacts out are Gemara YAML.

## How It Works

```
Scanner / CI pipeline                    
    │ Gemara YAML (EvaluationLog, EnforcementLog)
    ▼                                    
POST /api/ingest (JWT)                   
    │                                    
    ├── Verify publisher is trusted for this target
    ├── Append to Tessera transparency log
    ├── Queue for async processing (NATS JetStream)
    │       ↓
    │   Flatten → PostgreSQL → Certify → Trust signals
    │
    └── 202 Accepted {job_id, log_index}
                                         
GET /api/evidence?policy_id=X            → What evidence exists
GET /api/requirements                    → What's covered vs missing
GET /api/policies/discover?target_id=X   → Which policies apply to this target
GET /api/evidence/:id/verification       → Trust signals for this evidence
```

The gateway writes everything to Tessera first. PostgreSQL is a queryable cache — if you lose it, the transparency log is the source of truth. Independent witnesses cosign checkpoints for anti-equivocation verification. A separate content monitor (`cmd/monitor`) polls Tessera and verifies entry quality.

## Quick Start

```bash
# Start PostgreSQL and NATS
podman run -d --name pg -e POSTGRES_USER=complytime -e POSTGRES_PASSWORD=complytime \
  -e POSTGRES_DB=complytime -p 5432:5432 docker.io/library/postgres:16
podman run -d --name nats -p 4222:4222 docker.io/library/nats:latest -js -sd /data

# Build and run the gateway
export POSTGRES_URL="postgres://complytime:complytime@localhost:5432/complytime?sslmode=disable"
export NATS_URL="nats://localhost:4222"
make gateway-build
./bin/studio-gateway
```

```bash
# Submit an EvaluationLog
curl -X POST http://localhost:8080/api/ingest \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @evaluation-log.yaml

# Query evidence
curl http://localhost:8080/api/evidence?policy_id=my-policy

# Check posture
curl http://localhost:8080/api/requirements
```

### Run tests

```bash
make test                                  # Unit tests
make test-integration                      # Integration (needs POSTGRES_TEST_URL)
./scripts/e2e-enrollment-test.sh           # E2E (starts containers automatically)
```

### Deploy

See [studio-deploy](https://github.com/complytime/studio-deploy) for Helm chart and Docker Compose.

### Something not working?

- `make lint` — run linters locally
- Check `POSTGRES_URL` and `NATS_URL` are set and reachable
- Gateway logs to stdout with `slog` — look for `async ingest` messages

## Configuration

| Variable | Default | Purpose |
|:--|:--|:--|
| `POSTGRES_URL` | (required) | PostgreSQL connection string |
| `NATS_URL` | (required) | NATS server URL |
| `TESSERA_SIGNER_KEY_PATH` | (empty) | Persist Tessera signer key. Without this, the log identity changes on restart. |
| `INGEST_RATE_LIMIT` | `10` | Requests/second per IP on `/api/ingest` |
| `INGEST_RATE_BURST` | `20` | Burst allowance for rate limiting |

## ComplyTime Ecosystem

| Repository | What it does |
|:--|:--|
| **complytime-core** (this repo) | Evidence pipeline — ingest, verify, store, query |
| [complyctl](https://github.com/complytime/complyctl) | CLI — scan targets, produce evidence, pull policies from OCI |
| [complytime-studio](https://github.com/complytime-labs/complytime-studio) | Audit workbench — AI agents draft audit artifacts |
| [studio-ui](https://github.com/complytime/studio-ui) | Analyst dashboard |
| [studio-deploy](https://github.com/complytime/studio-deploy) | Helm chart + Docker Compose |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | Framework crosswalking — map requirements across standards |

All tools produce and consume [Gemara](https://gemara.openssf.org/) YAML artifacts. No tool requires any other to function.

## Learn More

- [Architecture](docs/architecture.md) — component boundaries and communication
- [Architecture Decision Records](docs/decisions/) — why things are the way they are
- [AGENTS.md](AGENTS.md) — guide for AI coding agents working on this codebase
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [Service Level Requirements](docs/requirements/service-level-requirements.md) — SLRs and gap analysis

## License

[Apache License 2.0](LICENSE)
