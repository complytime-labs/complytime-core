# ADR-0003: Receipt Model — Unified in-toto Attestation

## Status

Accepted (supersedes original two-entry DSSE model, updated 2026-07-21)

## Context

The evidence gateway wraps submitted artifacts with provenance metadata before
sealing them into the locker. We need a receipt format that:

- Binds channel identity (who submitted, when, with what authorization) to artifact content
- Preserves DSSE signature verifiability for cross-boundary signed evidence
- Uses standard formats recognizable by the supply chain security ecosystem
- Supports deterministic hashing for digest stability
- Keeps the locker content-agnostic (seals bytes without parsing)

## Decision

### All Artifacts: Single-Entry Receipt

Every artifact — unsigned JSON and DSSE-signed envelopes alike — is wrapped in
an in-toto v1 Statement with predicate type `gemara-receipt/v1`. The receipt
binds the publisher's channel identity to the artifact content.

Content is JCS-canonicalized (RFC 8785 via `cyberphone/json-canonicalization`)
before hashing. Content is base64-encoded in the predicate to avoid type
coercion through protobuf's `structpb.Struct`. The full receipt is
JCS-canonicalized after `protojson.Marshal` before sealing, ensuring digest
stability across protobuf library versions.

We use `github.com/in-toto/attestation/go/v1` (the canonical protobuf types)
rather than hand-rolled structs.

### Receipt Predicate

```json
{
  "content": "<base64-encoded JCS-canonicalized artifact>",
  "contentDigest": "sha256:<base64url hash>",
  "publisher": {"issuer": "<JWT issuer>", "sub": "<JWT subject>"},
  "artifactType": "<Gemara type or 'dsse'>",
  "receivedAt": "<RFC 3339 timestamp>"
}
```

- `publisher` — issuer and subject from the authenticated JWT, set at wrap
  time. Cannot be omitted.
- `receivedAt` — wall-clock time when the gateway received the artifact.
  Provides temporal context for audit trails.
- `artifactType` — the Gemara `metadata.type` value (e.g., `EvaluationLog`)
  or `"dsse"` for DSSE-signed envelopes.

### DSSE Handling (Changed)

The original two-entry model stored DSSE envelopes as separate ledger entries
with a companion `gemara-dsse-channel-receipt/v1`. This was dropped because:

1. The channel receipt was a derived index, not an independent attestation
2. No consumer used it
3. It doubled log volume per DSSE submission
4. It coupled the locker to receipt parsing (placeholder index rebuild pattern)
5. Persona review (auditor, practitioner, tooling dev) unanimously recommended removal

DSSE envelopes are now wrapped with `receipt.Wrap` using `artifactType: "dsse"`.
The DSSE bytes become the base64-encoded `content` field. Publisher attribution
is in the receipt predicate. DSSE signatures are preserved byte-exact through
base64 encoding and are recoverable by unwrapping the receipt and decoding
`content`.

### Locker Invariant

The locker is content-agnostic. It seals receipt bytes into the Tessera
transparency log without parsing or validating their contents. All receipts
are `gemara-receipt/v1` — the locker does not need to distinguish artifact
types or handle multiple receipt formats.

### Gemara Validation

The gateway validates raw artifacts against Gemara JSON Schemas (exported from
CUE) before wrapping them into receipts. Invalid artifacts are rejected
synchronously (422) before any NATS publishing. DSSE artifacts skip Gemara
validation — the DSSE payload is opaque to the gateway.

### DSSE Signature Verification

The gateway does NOT verify DSSE signatures. It wraps the entire DSSE envelope
as opaque content. Signature verification is a consumer-edge concern.

## Consequences

- One receipt format in the locker (`gemara-receipt/v1`) — simpler for all consumers
- One log entry per submission regardless of artifact type
- DSSE signatures preserved through base64 encoding (verified by #246)
- Locker is fully content-agnostic — seals bytes, serves tiles
- `UnwrapContent()` helper simplified — only handles `gemara-receipt/v1`
- Publisher identity and timestamp in every receipt — audit trail complete

## Related

- [ADR-0005](./0005-gateway-as-gemara-collector.md) — gateway/locker separation
