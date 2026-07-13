# Hash-Chained Audit Provenance Deferred

**Status:** Superseded by [Transparency Ledger](transparency-ledger.md)
**Date:** 2026-04-29 (original), 2026-05-27 (superseded)

## Decision

~~Studio will not add hash-chained provenance to the audit_logs table. Tamper-evident audit trails are deferred until a verifiable log infrastructure justifies the complexity.~~

**Superseded:** The trigger condition (verifiable log infrastructure) has been met. Tessera provides the tamper-evident transparency log that this ADR identified as the recommended path. See [Transparency Ledger](transparency-ledger.md) for the accepted architecture.

## Original Context

This ADR evaluated in-database hash chains for audit provenance and deferred in favor of a proper transparency log (Trillian was the candidate at the time). The core reasoning remains valid: in-database hash chains are self-referential and rewritable by anyone with database access. External verifiable infrastructure is required for real tamper-evidence.

## Resolution

Tessera (Trillian's successor) was integrated in May 2026. All evidence submissions — including artifacts that become audit log inputs — are appended to the Tessera transparency log with cryptographic ordering and independent witness verification. The `log_index` column on database tables links queryable data back to its immutable log entry.
