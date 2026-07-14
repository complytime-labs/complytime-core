# ADR-0003: Receipt Model — in-toto Attestation with Two-Entry DSSE

## Status

Accepted

## Context

The evidence gateway wraps submitted artifacts with provenance metadata before sealing them into the locker. We need a receipt format that:

- Binds channel identity (who submitted, when, with what authorization) to artifact content
- Preserves DSSE signature verifiability for cross-boundary signed evidence
- Uses standard formats recognizable by the supply chain security ecosystem
- Supports deterministic hashing for digest stability

## Decision

### Unsigned Artifacts: Single-Entry Receipt

Unsigned artifacts are wrapped in an in-toto v1 Statement with predicate type `gemara-receipt/v1`. The receipt binds the publisher's channel identity to the artifact content.

Content is JCS-canonicalized (RFC 8785 via `cyberphone/json-canonicalization`) before hashing. Content is base64-encoded in the predicate to avoid type coercion through protobuf's `structpb.Struct`. The full receipt is JCS-canonicalized after `protojson.Marshal` before sealing, ensuring digest stability across protobuf library versions.

We use `github.com/in-toto/attestation/go/v1` (the canonical protobuf types) rather than hand-rolled structs. The only custom helper is a `predicateToStruct` function that converts typed Go predicates into `*structpb.Struct` via JSON marshaling.

### DSSE-Signed Artifacts: Two-Entry Model

DSSE envelopes are stored byte-exact as their own ledger entry. A separate DSSE channel receipt (`gemara-dsse-channel-receipt/v1`) is sealed immediately after, referencing the DSSE entry by content digest.

This avoids nesting an in-toto Statement inside a DSSE envelope inside another in-toto Statement — three layers of envelopes that would:

1. Risk byte-level changes through `structpb`/`protojson` serialization, breaking DSSE signature verification downstream
2. Create three parsing layers for every consumer
3. Not match how audit evidence works (artifacts and chain-of-custody forms are separate documents)

### Locker Invariant

The locker stores only attributed entries:

- **Receipts** — unsigned artifacts with channel trust
- **DSSE envelopes** — signed artifacts with portable trust (self-attributing via producer signature)
- **Channel attestations** — companion entries binding DSSE submissions to the authenticated channel

### DSSE Signature Verification

The gateway does NOT verify DSSE signatures. It validates envelope structure (valid JSON, payload present, at least one signature) but does not verify cryptographic signatures. Verification is a consumer-edge concern — the monitor service will verify signatures and seal verification results back through the gateway. Until the monitor exists, DSSE evidence has channel trust (receipt/attestation) but unverified content trust.

## Consequences

- Two entry formats in the locker instead of one, requiring consumers to handle both
- DSSE sealing requires two entries (atomicity handled by idempotent retry via `VerifyDigest`)
- An `UnwrapContent()` helper in the receipt package abstracts the two formats for consumers
- CloudEvents carry `contentFormat` so consumers know what was sealed before fetching
