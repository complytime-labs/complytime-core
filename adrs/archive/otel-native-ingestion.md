# OTel-Native Ingestion via Collector

**Status:** Superseded by [Unified Ingest Pipeline](unified-ingest-pipeline.md) and architecture clarification (2026-05-29)
**Date:** 2026-04-21

## Superseded By

This ADR described evidence flowing from complyctl → OTel Collector → ClickHouse exporter → evidence table. The architecture has since changed:

1. **PostgreSQL replaced ClickHouse** for evidence storage
2. **Unified ingest pipeline** (`POST /api/ingest` → Tessera → NATS → worker) replaced direct database writes
3. **OTLP path clarified** as observability-only (compliance metrics and scan traces for SRE dashboards), NOT evidence ingestion

**Current architecture (2026-05-29):**

```
complyctl scan → Gemara EvaluationLog
  ├─ POST /api/ingest → Tessera → PostgreSQL (evidence path)
  └─ OTLP logs → Beacon → observability backend (telemetry path)
```

Evidence ingestion is Gemara-native via `POST /api/ingest`. OTLP provides observability metrics for SREs.

See:
- [Unified Ingest Pipeline](unified-ingest-pipeline.md) — all Gemara artifacts flow through a single async pipeline
- [Import Through Tessera](import-through-tessera.md) — OCI bundles also route through Tessera
- Issue #38 — Enrichment pipeline removal

---

**Original ADR text below for historical reference:**

## Decision

Evidence ingestion from complyctl/ProofWatch flows through the OTel Collector's ClickHouse exporter directly into the `evidence` table. Studio does not implement an OTLP receiver, custom exporter, or standalone ingest binary.

## Context

complyctl now emits OTel log records via the ProofWatch instrumentation library using `evidence` semantic conventions. The question was how those logs reach Studio's ClickHouse `evidence` table.

Three options were evaluated:

| Option                                    | Rejected Because                                                                                                                                 |
|:------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| OTLP receiver in gateway                  | Heavy — requires parsing OTLP protobuf/JSON, mapping ~30 attributes, handling batching/status codes. Duplicates what the Collector already does. |
| Custom Studio exporter for OTel Collector | Maintains an OTel Collector plugin in a separate repo. Tied to collector release cycle. Too much surface area for "write rows to a table."       |
| `cmd/ingest` standalone binary            | Parallel ingest path outside the collector. No reason to exist when the collector handles the same job.                                          |

## Architecture

```
complyctl scan
     │
     ▼
ProofWatch (instrumentation lib)
Emits OTel logs with beacon.evidence semconv
     │
     ▼
OTel Collector (operator-managed)
├── OTLP receiver
└── ClickHouse exporter → evidence table
     │
     ▼
ClickHouse (Studio owns DDL)
     │
     ▼
Studio reads via clickhouse-mcp + REST APIs
```

## Responsibility Split

| Repo | Owns |
|:--|:--|
| `complytime-collector-components` | Collector config, ClickHouse exporter attribute→column mapping |
| `complyctl` / ProofWatch | Instrumentation, semconv attribute emission |
| `complytime-core` | `evidence` table DDL, query APIs, assistant |

The interface contract is `docs/design/evidence-semconv-alignment.md`. The exporter **MUST** map `compliance.source.registry` to the `source_registry` column (and every other attribute listed there to the named column) so OTel rows match REST-shaped queries.

Environment-specific collector YAML lives in operator or platform repos; keep attribute names aligned with the semconv doc even when endpoints or credentials differ.

## Consequences

- `Dockerfile.ingest` and `cmd/ingest` are removed.
- Studio has no OTLP parsing code. The gateway stays a REST/A2A server.
- `POST /api/evidence` and `POST /api/ingest` remain for seeding, manual import, non-OTel producers, and unified Gemara jobs.
- Schema changes to the `evidence` table require coordinated updates to the semconv alignment doc and collector exporter config.
- The OTel Collector remains operator infrastructure per the existing [OTel Collector Out of Chart](otel-collector-out-of-chart.md) decision.
