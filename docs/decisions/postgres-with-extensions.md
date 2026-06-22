# ADR-0001: PostgreSQL as Primary Persistence Layer

**Status:** Superseded by [Remove PostgreSQL](remove-postgresql.md)
**Date:** 2026-05-01
**Supersedes:** dual-store-data-layer (native ClickHouse client + PostgreSQL)

## Problem

ComplyTime Studio serves two competing workloads:

- **Transactional** — programs, users, notifications, draft audit logs, role changes. Small reads/writes, foreign key integrity, row-level updates.
- **Analytical** — evidence posture aggregates, requirement coverage matrices, time-series trend queries. Append-heavy, scan-heavy, retained for years.

The original architecture chose ClickHouse for the analytical workload. The audit dashboard pivot (ADR-0004) added the transactional workload. ClickHouse has no foreign keys, no transactions, no row-level updates — every transactional operation fought the engine.

The dual-store attempt (native Go ClickHouse client + PostgreSQL) required cross-store query orchestration, two connection strings, two migration systems, and partial failure handling. The application had to know which database owned which table. Complexity disproportionate to prototype scale.

## Decision

**PostgreSQL 16+ as the single application database.** All application code writes standard PostgreSQL SQL against one connection pool. Evidence separation happens at the infrastructure level via `pg_clickhouse` FDW, not at the application level.

Two deployment modes, same application code:

| Mode | Evidence storage | Infrastructure | When |
|:--|:--|:--|:--|
| Default | Native PostgreSQL tables | Gateway + PostgreSQL | Prototyping, small teams, single-instance |
| Production | ClickHouse via `pg_clickhouse` FDW | Gateway + PostgreSQL + ClickHouse | Evidence volume exceeds PostgreSQL scan performance |

The `pg_clickhouse` extension (Apache 2.0, ClickHouse Inc.) creates foreign tables in PostgreSQL that transparently proxy reads and writes to ClickHouse. JOINs between native tables (programs, users) and foreign tables (evidence) work as standard SQL. Analytical queries push down to ClickHouse for execution.

ClickHouse was the right engine for the original evidence-heavy, analytics-first scope. It remains the right engine for evidence at scale. The change is that it's no longer a required default — it's an operator decision based on data volume.

## Alternatives Considered

| Alternative | Verdict |
|:--|:--|
| Dual-store (native ClickHouse client + PostgreSQL) | Rejected — cross-store orchestration, two migration systems, partial failure handling. Application code carried the integration burden. |
| ClickHouse only | Rejected — no referential integrity, no transactions. Every transactional operation (programs, users, notifications) fought the engine. |
| PostgreSQL + `pg_duckdb` | Rejected — DuckDB provides columnar acceleration inside PostgreSQL but is an in-process engine. No independent scaling of the analytical tier. Evidence retention and query load compete with transactional work in the same process. `pg_clickhouse` separates the analytical engine entirely. |
| DuckDB standalone | Rejected — embedded engine, no multi-process access, no independent HA story. Same in-process limitation as `pg_duckdb`. |
| SQLite | Rejected — multi-process deployment requirement, no user/role separation. |
| MongoDB | Rejected — loses transactional JOINs, FK constraints, role-based defense-in-depth. |

## Consequences

**Upside:**
- Single connection pool, single migration system, single query language.
- Default install: two services (gateway + PostgreSQL).
- Evidence schema evolves independently — the operator provisions ClickHouse and creates foreign tables. Application code does not change.
- `pg_clickhouse` FDW means the analytical engine scales independently: separate hardware, separate retention policies, separate backup schedules.

**Downside:**
- Coupled to PostgreSQL semantics. Re-targeting MySQL would require rewriting queries.
- Production mode adds ClickHouse as a third service. Operator must configure FDW, foreign tables, and ClickHouse schema.
- FDW has overhead for simple queries that PostgreSQL handles natively. Default mode is faster for small datasets.

**When to revisit:** If a downstream operator needs a non-Postgres backend, pull the storage layer behind a Go interface and provide a second implementation. Not on the v1 roadmap.
