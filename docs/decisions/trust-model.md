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

| Tier | Mechanism                          | Use case                                                 |
| :--- | :--------------------------------- | :------------------------------------------------------- |
| 0    | JWT + Tessera + witness            | Single-party direct submission (ISO 27001, SOC 2)        |
| 1    | Unsigned in-toto receipt           | Durable channel identity in log                          |
| 2    | DSSE-signed individual attestations | Multi-party flows (CRA: lab + manufacturer + reviewer)  |
| 3    | Signed bundle attestation (AuditLog) | Certification-level assertions                         |

Each tier is independently useful. Currently Phase 0 implements Tiers 0-1.

## Admin vs Publisher Separation

Target registration and trust management are admin operations, distinguished from evidence publishing by Cedar action:
- `admin:register-target` — TargetRegistration artifacts
- `admin:manage-trust` — trust modification (future)
- `publish:artifact` — evidence submission (publishers group)

TargetRegistration is a **complytime-specific platform artifact**, not a Gemara type. It flows through the ingest pipeline and is logged to Tessera for auditability.

## Why Not Rekor

Rekor exposes data on public unauthenticated endpoints. Compliance evidence is organizational data requiring authenticated reads. Core provides private transparency — tamper-evident and auditable, but access-controlled. Core also understands Gemara schemas, enabling domain-specific validation and typed event routing that a generic log cannot provide.

## Related Decisions

- [Transparency Ledger](transparency-ledger.md) — Tessera as the immutable log (still valid, entry format updated by this ADR)
- [Content Verification Service](content-verification-service.md) — monitor role (content quality verification, distinct from witnessing)
- [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) — witness cosignatures for non-equivocation
- [Remove PostgreSQL](remove-postgresql.md) — database removed, NATS KV for runtime state
