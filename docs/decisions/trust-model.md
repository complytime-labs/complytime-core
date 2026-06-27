# Trust Model: Private Gemara Evidence Gateway

**Status:** Accepted
**Date:** 2026-06-27
**Supersedes:** trust-signals-certification.md (PostgreSQL trust signals removed with database)

## Decision

complytime-core is a **private Gemara evidence gateway** — not a generic transparency log. It authenticates publishers, validates Gemara artifacts, wraps entries with provenance metadata as in-toto v1 Statements, appends to Tessera, and notifies subscribers. Compliance evidence requires authenticated reads, which differentiates core from public transparency logs like Rekor.

## Core Responsibilities

1. **Authenticate** — OIDC/JWT verification at the ingest boundary (two paths: direct JWT Bearer for headless/M2M callers, OAuth2 Proxy headers for browser callers)
2. **Authorize** — Cedar policies for channel access (publishers, auditors, admins groups) with forbid safety floors
3. **Validate** — type detection at ingest boundary; full schema validation deferred to content monitor
4. **Wrap** — bind content + verified publisher identity as an unsigned in-toto v1 Statement (receipt, not attestation — DSSE signing comes at Tier 2+)
5. **Log** — append to Tessera (immutable, tamper-evident, witness-cosigned)
6. **Notify** — publish events to NATS for downstream consumers

## What Core Does NOT Do

- **Provenance** — supply chain provenance (who produced what from which inputs) belongs to in-toto attestations created by producers (CrossCodex, complyctl). Core records channel identity (who submitted), not build provenance.
- **Query** — subscribers build their own views from NATS events. CrossCodex is the query layer.
- **Certification pipeline** — removed. Trust signals and verification attestations will be redesigned on the new model.

## In-toto Statement Wrapping

Every Tessera entry is an in-toto v1 Statement (JSON) with predicate type `https://complytime.dev/gemara-receipt/v1`. The predicate contains:
- The raw Gemara artifact content
- The verified publisher identity (issuer, subject, authentication method)
- Artifact type and ingestion timestamp

This ensures publisher identity is durably stored in the immutable log, not carried ephemerally through NATS messages. The `in-toto/attestation` v1.2.0 SDK is used with `protojson` serialization for spec-compliant JSON output.

The `ingestedAt` timestamp is server-clock-asserted — it records when core received the submission, not when the evidence was produced. Witnessed timestamps (externally attested) arrive at Tier 2+ with DSSE-signed attestations.

For DSSE-signed submissions (future — Phase 2), the entire DSSE envelope is stored as the Tessera entry. Core verifies the signature and records both signing identity (publisher) and channel identity.

## Trust Tiers

Not all compliance evidence requires the same provenance level:

| Tier | Mechanism                            | Use case                                      |
| :--- | :----------------------------------- | :-------------------------------------------- |
| 0    | JWT + Tessera + witness              | Single-party, direct submission               |
| 1    | Unsigned in-toto receipt             | Durable channel identity in log               |
| 2    | DSSE-signed individual attestations  | Multi-party, intermediary flows               |
| 3    | Signed bundle attestation (AuditLog) | Certification-level assertions                |

Each tier is independently useful. Currently Phase 0 implements Tiers 0-1.

## Admin vs Publisher Separation

Target registration and trust management are admin operations, distinguished from evidence publishing by Cedar action:
- `admin:register-target` — TargetRegistration artifacts
- `admin:manage-trust` — trust modification (future)
- `publish:artifact` — evidence submission (publishers group)

TargetRegistration is a **complytime-specific platform artifact**, not a Gemara type. It flows through the ingest pipeline and is logged to Tessera for auditability.

## Why a Purpose-Built Sink

Public transparency logs are designed for open verification — anyone can read and post. Compliance evidence has different requirements:

- **Authenticated reads** — compliance evidence is organizational data, not public
- **Authorized writes** — submitters must be authorized for the specific target they claim evidence about. A signed artifact alone is not sufficient; the system of record must verify the signer is authorized to make claims about that target.
- **Domain-specific validation** — only well-formed Gemara artifacts are accepted
- **Typed event routing** — downstream consumers subscribe by target and artifact type

complytime-core is a **system of record** for compliance decisions. CrossCodex is the **system of analysis** that queries and correlates. These roles must not be conflated — a system of record must be selective about what it accepts; a system of analysis must be comprehensive about what it queries.

## What Goes in Tessera

Gemara artifacts are **summaries of compliance decisions**, not raw evidence. An EvaluationLog records "control AC-1 passed for target X" — it does not contain the raw scan output, configuration file, or API response that was evaluated. Raw evidence stays at its source and is referenced by digest via Gemara's `EvidenceMapping` (ADR-0023).

Tessera stores summaries because they are the compliance decisions that need tamper-evidence and non-repudiation. The raw evidence doesn't need an append-only log because the summary's reference to it (with content hash) is already immutable in Tessera. If the raw source changes after the assessment, the digest mismatch is detectable.

This means Tessera entries are small (kilobytes, not megabytes), and embedding Gemara content inline in the in-toto predicate is the correct model.

## Predicate Types

Two predicate types distinguish trust levels:

**`https://complytime.dev/gemara-receipt/v1`** — sink-generated, unsigned. The sink verified the channel identity and wrapped the content. Trust comes from the sink's verification + Tessera immutability.

```json
{
  "content": { "metadata": {"type": "EvaluationLog"}, "..." : "..." },
  "publisher": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:acme/myapp",
    "method": "jwt-channel"
  },
  "channel": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:acme/myapp"
  },
  "artifactType": "EvaluationLog",
  "ingestedAt": "2026-06-27T20:00:00Z"
}
```

**`https://complytime.dev/gemara-attestation/v1`** (Phase 2) — producer-signed via DSSE. The producer signed the content before delivery. Trust comes from the cryptographic signature. The sink verified the signature and stored the entire DSSE envelope.

```json
{
  "content": { "metadata": {"type": "EvaluationLog"}, "..." : "..." },
  "producer": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:acme/myapp",
    "keyId": "sha256:abc123..."
  },
  "artifactType": "EvaluationLog",
  "producedAt": "2026-06-27T19:55:00Z"
}
```

The receipt carries the **sink's perspective** (who submitted, when received). The attestation carries the **producer's perspective** (who produced, when produced). Consumers check the predicate type to know which trust model applies.

## Relationship to ADR-0014

ADR-0014 (Signed Evidence Attestation Pipeline) defines the delivery model: producers sign evidence with DSSE, an untrusted transport moves it, and the consumer verifies at its edge. complytime-core is the **mandatory transparency-log sink** that ADR-0014 requires for the compliance profile.

The sink's responsibilities in ADR-0014's model:
- Verify DSSE signatures against trust anchors (Phase 2)
- Verify the signer is authorized for the claimed target (publisher trust)
- Append to the transparency log (Tessera)
- Provide non-equivocation via witness cosignatures

For unsigned submissions (Tier 0-1), the sink generates receipts. For signed submissions (Tier 2+), the sink verifies and stores the producer's attestation.

## Related Decisions

- [ADR-0014: Signed Evidence Attestation Pipeline](https://github.com/complytime/complytime/pull/31) — upstream ADR defining the delivery model (trust the payload, not the pipe). This trust model defines what the transparency-log sink does with the signed evidence ADR-0014 delivers.
- [Transparency Ledger](transparency-ledger.md) — Tessera as the immutable log (still valid, entry format updated by this ADR)
- [Content Verification Service](content-verification-service.md) — monitor role (content quality verification, distinct from witnessing)
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — witness cosignatures for non-equivocation
- [Remove PostgreSQL](remove-postgresql.md) — database removed, NATS KV for runtime state
