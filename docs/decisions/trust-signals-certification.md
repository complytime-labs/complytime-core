# Trust Signals Replace Binary Certified Flag

**Status:** Accepted  
**Date:** 2026-06-01  
**Supersedes:** Binary `certified` boolean column

## Decision

Trust signals are the sole source of certification status. The `evidence.certified` boolean column and `certifications` table are removed. Certification results are stored as queryable trust signals in the `trust_signals` table, enabling granular verification and agent-driven workflows.

## Context

The original certification model used a binary `certified` boolean on each evidence row, computed by aggregating verdicts from multiple certifiers. This had several limitations:

1. **Opaque**: "Why did this fail?" required querying a separate `certifications` table
2. **Not queryable**: "Show me evidence with valid publisher but no witness verification" was impossible
3. **Agent-hostile**: External agents couldn't filter by specific verification checks
4. **Temporal confusion**: Freshness was treated as immutable certification when it's actually temporal

The trust signals model stratifies verification into three queryable layers:
- **Identity** - immutable properties (schema, provenance, publisher authorization)
- **Quality** - immutable checks (relevance, completeness)
- **Attestation** - client-side verification (witness, audit review)

## Architecture

### Trust Signals Table

```sql
CREATE TABLE trust_signals (
    evidence_id TEXT NOT NULL,
    layer TEXT NOT NULL,  -- 'identity', 'quality', 'attestation'
    check_name TEXT NOT NULL,
    result TEXT NOT NULL,  -- 'pass', 'fail', 'skip', 'error'
    reason TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (evidence_id, layer, check_name)
);
```

### Certification Flow

```
POST /api/ingest
  ↓
Tessera append
  ↓
NATS async processing
  ↓
Certification Pipeline:
  ├─ SchemaCertifier → trust_signal(identity/schema)
  ├─ ProvenanceCertifier → trust_signal(identity/provenance)
  ├─ ExecutorCertifier → trust_signal(identity/executor)
  └─ PublisherAuthCertifier → trust_signal(identity/publisher-authorized)
  
Client queries:
  SELECT * FROM trust_signals WHERE evidence_id = X
  → All checks visible, filterable, queryable
```

### Query Pattern

**Old (opaque boolean):**
```sql
SELECT * FROM evidence WHERE certified = true
-- Why is it certified? Unknown without second query
```

**New (queryable signals):**
```sql
-- Evidence with all identity checks passing
SELECT e.* FROM evidence e
WHERE NOT EXISTS (
  SELECT 1 FROM trust_signals
  WHERE evidence_id = e.evidence_id
  AND layer = 'identity'
  AND result IN ('fail', 'error')
)

-- Evidence schema-valid but missing witness attestation
SELECT e.* FROM evidence e
WHERE EXISTS (
  SELECT 1 FROM trust_signals
  WHERE evidence_id = e.evidence_id
  AND layer = 'identity' AND check_name = 'schema' AND result = 'pass'
)
AND NOT EXISTS (
  SELECT 1 FROM trust_signals
  WHERE evidence_id = e.evidence_id
  AND layer = 'attestation' AND check_name = 'witness-verified'
)
```

## Migration

**Breaking change** - no backward compatibility:

1. Migration 031 drops `evidence.certified` column
2. Migration 031 drops `certifications` table
3. `AggregateCertified()` function removed
4. `UpdateEvidenceCertified()` method removed
5. Certification handler writes ONLY trust signals

**Witness adaptation:**
- External witness queries `HasFailedTrustSignals()` instead of checking `certified` boolean
- Witness writes attestations back to Tessera as in-toto Statements (client-side)

## Benefits

### For Agents
- **Queryable**: "Show evidence where schema passed but publisher failed"
- **Composable**: Each agent adds signals, next agent queries them
- **Transparent**: See exactly which checks ran and their results

### For Auditors
- **Granular**: Per-check results, not binary pass/fail
- **Traceable**: Follow evidence through verification layers
- **Temporal clarity**: Immutable signals (identity/quality) vs temporal queries (freshness)

### For the Evidence Chain
```
Entry #100: EvaluationLog
  ├─ trust_signal(identity/schema = pass)
  ├─ trust_signal(identity/publisher-authorized = pass)
  └─ trust_signal(attestation/witness-verified = pass) ← added by witness agent

Entry #101: AuditLog (references #100)
  └─ trust_signal(attestation/audit-reviewed = pass) ← added by audit agent
```

Each verification layer is queryable. Agents build on previous verification work.

## Alternatives Considered

### Keep `certified` as Denormalized Cache

**Rejected** - adds complexity with no benefit:
- Requires `AggregateCertified()` to compute from signals
- Dual-write (signals + boolean) creates consistency risk
- Clients still need to query signals for granular filtering
- Cache invalidation problem (what if signals change?)

### Use Certifications Table Instead

**Rejected** - certifications table lacked structure:
- No layer concept (identity vs attestation mixed)
- No composite key (could have duplicate certifier entries)
- Not designed for querying ("show evidence with publisher check passing")

## Key Principles

1. **Core = Identity Layer** - Authentication, immutable facts
2. **Clients = Trust Layer** - Authorization, temporal policies
3. **Certification Pipeline = Immutable Properties** - Schema, provenance, publisher
4. **Query APIs = Temporal Properties** - Freshness, coverage, relevance to current policy
5. **Trust Signals Enable Evidence Chain** - Each agent adds queryable verification

## Related Decisions

- [ADR 0036: Transparency Ledger (Tessera)](transparency-ledger.md) - Immutable evidence storage
- [ADR 0037: Witness Service](witness-service.md) - External verification (now client-side)
- [Epic #71: Trusted Publishing](https://github.com/complytime-labs/complytime-core/issues/71) - Publisher authorization
- [Epic #72: Certification Pipeline](https://github.com/complytime-labs/complytime-core/issues/72) - Trust signals implementation

## Implementation

- Migration: `internal/postgres/migrations/031_drop_certified_column.sql`
- Trust signals: `internal/store/store_trust_signals.go`
- Certification handler: `internal/events/certification_handler.go`
- PR: #69 - Trust Signals Phase 1
