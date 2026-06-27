# ComplyTime Core

Private Gemara evidence gateway — the system of record for compliance decisions.

> **Status:** Active redesign — this repo is being restructured into a focused evidence gateway with in-toto provenance and target-scoped trusted publishing ([#179](https://github.com/complytime-labs/complytime-core/issues/179), [#128](https://github.com/complytime-labs/complytime-core/issues/128)). APIs, schema, and project scope are changing. Expect volatility.
>
> **Built with AI:** Code, documentation, architecture decisions, and design specs are authored collaboratively with LLM tools (Claude Code, Cursor). PRs are labeled `llm-assisted`.

## Why

Proving your systems are compliant means collecting evidence from scanners, CI pipelines, and manual reviews — then assembling it into something an auditor can verify. Today that evidence is scattered across tools, unverifiable after the fact, and manually stitched together at audit time.

ComplyTime Core is the evidence gateway that fixes this:

- **Every submission is wrapped as an in-toto Statement** — binding the Gemara artifact with verified publisher identity before appending to a tamper-evident transparency log. You can prove what was submitted, by whom, and that it hasn't changed.
- **Publisher identity is cryptographically verified** — JWT-authenticated OIDC identities tied to targets. A CI pipeline can only submit evidence for infrastructure it's authorized to assess.
- **Independent witnesses cosign checkpoints** — anti-equivocation verification ensures all parties see the same log.
- **The content monitor independently verifies entries** — schema validation, reference integrity, and producer identity verification run as an independent process against the log.

Built around the [OpenSSF Gemara](https://gemara.openssf.org/) compliance schema. Gemara artifacts are compliance decision summaries — not raw evidence. Raw evidence stays at its source and is referenced by digest.

## How It Works

```text
Scanner / CI pipeline
    │ Gemara artifact (EvaluationLog, Policy, TargetRegistration)
    ▼
POST /api/ingest (JWT)
    │
    ├── Cedar authorization (channel access + target-scoped trust)
    ├── Wrap as in-toto v1 Statement (content + publisher identity)
    ├── Append to Tessera transparency log
    ├── Queue for async processing (NATS JetStream)
    │
    └── 202 Accepted {job_id, log_index}

GET /api/entry/:index          → Individual log entry (in-toto Statement)
GET /checkpoint                → Cosigned checkpoint (signed note)
GET /tile/*                    → Merkle tree tiles + entry bundles
GET /log/witnessed/:index      → Witness cosignature coverage
```

Tessera is the source of truth. Publisher trust state lives in NATS KV, rebuildable from the log. Independent witnesses cosign checkpoints for anti-equivocation verification. A separate content monitor (`cmd/monitor`) polls Tessera and verifies entry quality.

## Roles

- **complytime-core** (this repo) is the **system of record** — it accepts, validates, wraps, and logs compliance decisions.
- **CrossCodex** is the **system of analysis** — it subscribes to events, builds a queryable graph, and answers compliance posture questions.

The monitor is the trust boundary between them — CrossCodex loads only entries the monitor has verified.

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
  -H "X-Forwarded-Groups: admins,publishers" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @examples/evaluation-log.yaml
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

## ComplyTime Ecosystem

| Repository | What it does |
| :-- | :-- |
| **complytime-core** (this repo) | Evidence gateway — ingest, verify, transparency log |
| [complyctl](https://github.com/complytime/complyctl) | CLI — scan targets, produce evidence, pull policies from OCI |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | System of analysis — queryable compliance posture graph |

All tools produce and consume [Gemara](https://gemara.openssf.org/) artifacts. No tool requires any other to function.

## Learn More

- [Getting Started](docs/getting-started.md) — setup, configuration, and troubleshooting
- [Architecture](docs/architecture.md) — component boundaries and communication
- [Trust Model](docs/decisions/trust-model.md) — predicate types, trust tiers, and upstream alignment
- [Architecture Decision Records](docs/decisions/) — why things are the way they are
- [AGENTS.md](AGENTS.md) — guide for AI coding agents working on this codebase
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## License

[Apache License 2.0](LICENSE)
