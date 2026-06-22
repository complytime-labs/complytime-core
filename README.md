# ComplyTime Core

Compliance evidence ingestion with cryptographic guarantees. Submit assessment results, get verifiable posture.

> **Status:** Active redesign — this repo is being restructured from a monolithic pipeline to a focused ingestion and trust boundary service ([#128](https://github.com/complytime-labs/complytime-core/issues/128)). APIs, schema, and project scope are changing. Expect volatility.
>
> **Built with AI:** Code, documentation, architecture decisions, and design specs are authored collaboratively with LLM tools (Claude Code, Cursor). PRs are labeled `llm-assisted`.

## Why

Proving your systems are compliant means collecting evidence from scanners, CI pipelines, and manual reviews — then assembling it into something an auditor can verify. Today that evidence is scattered across tools, unverifiable after the fact, and manually stitched together at audit time.

ComplyTime Core is the ingestion service that fixes this:

- **Every piece of evidence is Tessera-anchored** — appended to a tamper-evident transparency log before anything else happens. You can prove what was submitted, when, and that it hasn't changed.
- **Publisher identity is cryptographically verified** — JWT-authenticated OIDC identities tied to targets. A CI pipeline can only submit evidence for infrastructure it's authorized to assess.
- **Independent witnesses cosign checkpoints** — anti-equivocation verification ensures all parties see the same log.
- **Trust signals are computed at ingest** — schema validation, provenance checks, and executor verification run as certifiers in the async pipeline.

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
    │   Certify → Trust signals (NATS events)
    │
    └── 202 Accepted {job_id, log_index}

GET /checkpoint                → Cosigned checkpoint (signed note)
GET /tile/*                    → Merkle tree tiles + entry bundles
GET /log/witnessed/:index      → Witness cosignature coverage
```

Tessera is the source of truth. Publisher trust state lives in NATS KV, rebuildable from the log. Independent witnesses cosign checkpoints for anti-equivocation verification. A separate content monitor (`cmd/monitor`) polls Tessera and verifies entry quality.

## Quick Start

```bash
# Setup witness keys and start the stack
./scripts/setup-witness.sh
cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d

# Get a test JWT
TOKEN=$(curl -s http://localhost:9090/token?sub=repo:complytime-labs/complytime-core)

# Submit an EvaluationLog
curl -X POST http://localhost:8080/api/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-Email: dev@complytime.dev" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @evaluation-log.yaml
```

### Run tests

```bash
make test                # Unit tests
make test-integration    # Integration (Ginkgo, in-process Tessera)
```

### Smoke test

```bash
./scripts/smoke-test.sh  # Full stack verification (requires compose up)
```

### Something not working?

- `make lint` — run linters locally
- Check `NATS_URL` is set and reachable
- Ingest service logs to stdout with `slog` — look for `async ingest` messages

## Configuration

| Variable | Default | Purpose |
|:--|:--|:--|
| `NATS_URL` | (required) | NATS server URL |
| `TESSERA_PATH` | `/data/tessera` | POSIX storage path for the transparency log |
| `TESSERA_SIGNER_KEY_PATH` | (empty) | Persist Tessera signer key. Without this, the log identity changes on restart. |
| `JWT_ISSUERS` | (empty) | Comma-separated OIDC issuer URLs for publisher JWT verification |
| `JWT_AUDIENCE` | `complytime-core` | Expected JWT audience claim |
| `INGEST_RATE_LIMIT` | `10` | Requests/second per IP on `/api/ingest` |
| `INGEST_RATE_BURST` | `20` | Burst allowance for rate limiting |

## ComplyTime Ecosystem

| Repository | What it does |
|:--|:--|
| **complytime-core** (this repo) | Evidence ingestion — ingest, verify, transparency log |
| [complyctl](https://github.com/complytime/complyctl) | CLI — scan targets, produce evidence, pull policies from OCI |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | Framework crosswalking — map requirements across standards |

All tools produce and consume [Gemara](https://gemara.openssf.org/) YAML artifacts. No tool requires any other to function.

## Learn More

- [Architecture](docs/architecture.md) — component boundaries and communication
- [Architecture Decision Records](docs/decisions/) — why things are the way they are
- [AGENTS.md](AGENTS.md) — guide for AI coding agents working on this codebase
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## License

[Apache License 2.0](LICENSE)
