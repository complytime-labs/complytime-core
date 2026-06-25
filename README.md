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

```text
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

## ComplyTime Ecosystem

| Repository | What it does |
| :-- | :-- |
| **complytime-core** (this repo) | Evidence ingestion — ingest, verify, transparency log |
| [complyctl](https://github.com/complytime/complyctl) | CLI — scan targets, produce evidence, pull policies from OCI |
| [CrossCodex](https://github.com/complytime-labs/crosscodex) | Framework crosswalking — map requirements across standards |

All tools produce and consume [Gemara](https://gemara.openssf.org/) YAML artifacts. No tool requires any other to function.

## Learn More

- [Getting Started](docs/getting-started.md) — quick start, configuration, and troubleshooting
- [Architecture](docs/architecture.md) — component boundaries and communication
- [Architecture Decision Records](docs/decisions/) — why things are the way they are
- [AGENTS.md](AGENTS.md) — guide for AI coding agents working on this codebase
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## License

[Apache License 2.0](LICENSE)
