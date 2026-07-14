# OTel Collector Is Environment Infrastructure

**Status:** Accepted
**Date:** 2026-04-18

## Decision

The OTel Collector is not deployed by the ComplyTime Studio Helm chart. Cluster operators provision and manage collectors independently as environment infrastructure.

## Context

The Studio chart previously included an optional OTel Collector deployment (`otel.enabled=true`) that received OTLP evidence signals and exported them to ClickHouse. This coupled the collector's lifecycle, configuration, and credentials to the application chart.

Evidence producers (complyctl/ProofWatch, policy engines, admission controllers) exist across namespaces and clusters. The collector is one of many possible intake topologies — central gateway, sidecar, agent-local, or direct insert. The application chart should not prescribe which topology the operator uses.

## Consequences

- Studio chart no longer manages collector deployment, image versions, or resource limits.
- Cluster operators deploy collectors using their preferred method (OTel Operator, standalone Helm chart, sidecar injection).
- `POST /api/evidence` and `POST /api/evidence/upload` remain for local development and manual import without a collector.
- ClickHouse connection details for the collector exporter are the operator's responsibility.
- The `clickhouse.enabled` value still deploys the ClickHouse instance and schema for development use.

## Alternatives Considered

| Option | Rejected Because |
|:-------|:-----------------|
| Keep collector in chart, gated behind feature flag | Couples collector lifecycle to app deploys. Operator can't independently scale, configure, or version the collector. |
| Ship a separate collector sub-chart | Adds maintenance burden for infrastructure the operator likely already manages. |
