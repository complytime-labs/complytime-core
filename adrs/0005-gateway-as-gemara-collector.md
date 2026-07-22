# ADR-0005: Gateway as Gemara Collector, Locker as Content-Agnostic Trust Store

## Status

Accepted

## Date

2026-07-20

## Decision

The evidence gateway is a Gemara-aware collector that validates artifacts against CUE-exported JSON Schemas, wraps them in receipts, and embeds publisher identity. The locker is a content-agnostic trust store that seals bytes into the Tessera transparency log, manages ledgers, and handles administrative operations. Communication between gateway and locker uses NATS JetStream for evidence flow and HTTP for admin operations.

DSSE-signed artifacts follow the same path as unsigned artifacts: wrapped in receipts with channel identity. The separate DSSE channel receipt was removed—it was a derived index with no consumer and produced audit noise.

## Context

The original architecture had the gateway wrap receipts AND run a worker that called the locker over HTTP to seal evidence. The locker was a passive HTTP server. This created tight coupling:

- Gateway and worker shared in-memory state via `sync.Map`
- Gateway needed to know locker sealing details
- HTTP client/server ceremony for every evidence submission
- Worker logic split between gateway concerns and sealing mechanics

The refactor needed to:

1. Separate Gemara domain knowledge (gateway) from trust mechanics (locker)
2. Support independent scaling of collection vs. sealing
3. Enable the locker to serve multiple gateways or evidence sources
4. Make the boundary between services explicit

## Architecture

### Gateway Responsibilities

- Authenticate publishers via Cedar authorization
- Validate artifacts against Gemara CUE schemas (JSON Schema export)
- Wrap artifacts in in-toto receipts with channel identity
- Publish receipts to NATS JetStream subject `evidence.submitted`
- Expose HTTP API for job status polling
- Handle DSSE envelope structure validation (not signature verification)

### Locker Responsibilities

- Subscribe to `evidence.submitted` NATS subject
- Seal receipts into Tessera transparency log
- Manage ledger state (one log per subject, sharded by major version)
- Publish `evidence.sealed` and `evidence.failed` CloudEvents
- Expose HTTP admin API for ledger operations
- Content-agnostic: seals bytes without parsing Gemara schemas

### Communication

- **Evidence flow**: NATS JetStream (durable, at-least-once delivery)
- **Admin operations**: HTTP (ledger creation, status queries)
- **Job status**: not needed — 202 means accepted, JetStream guarantees delivery

### DSSE Handling

DSSE envelopes are sealed as-is (byte-exact preservation for signature verification). A single receipt wraps the DSSE envelope with channel identity. The two-entry model (separate DSSE channel receipt) was dropped:

- Derived from the same authentication event
- No consumer needed it
- Doubled audit log volume
- Added implementation complexity for no practical benefit

## Security Properties

| Property | Threat | Mechanism | Test |
|:--|:--|:--|:--|
| Publisher authorization | Unauthorized evidence injection | Cedar policies + NATS KV trust store. Gateway checks `IsPublisherTrusted` before accepting artifacts. Fail-closed. | acceptance: authenticated+untrusted returns 403 |
| Gemara schema validation | Invalid/malformed evidence enters the log | 13 CUE-exported JSON Schemas compiled at startup. Validation before receipt wrapping, before NATS publish. 422 on failure. | internal/gateway/validate_test.go, handler 422 test |
| Publisher identity in receipt | Falsified publisher attribution | `receipt.Wrap` reads issuer+sub from JWT context (set by authn middleware), writes to receipt predicate. Cannot be omitted. | internal/gateway/receipt/receipt_test.go |
| DSSE byte-exact preservation | Signature invalidation via content modification | DSSE bytes passed to `receipt.Wrap` as opaque content (base64-encoded). No re-serialization. | Pending: #246 |

Note: Control/threat catalog IDs will be assigned when Gemara catalogs are
created for this project. An unverified claim must not be stated as an
accepted guarantee — the DSSE byte-exact property is pending verification.

## Consequences

- Gateway can be deployed independently from locker
- Locker can serve multiple evidence sources (future: monitor, external collectors)
- NATS JetStream becomes critical infrastructure (already addressed via NATS HA)
- Schema updates happen at gateway boundary only
- Simpler DSSE path reduces sealing latency by ~50% (one Tessera call instead of two)

## Related

- [ADR-0001: Evidence Locker Architecture](./0001-evidence-locker-architecture.md) — original locker design
- [ADR-0003: Receipt Model](./0003-receipt-model.md) — in-toto attestation format
