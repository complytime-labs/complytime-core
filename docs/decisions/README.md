# Architecture Decision Records

Data platform decisions. ADRs crystallize specific decisions — propose one via
a PR when a [design discussion](https://github.com/complytime-labs/complytime-core/issues/new?template=design_discussion.yml)
converges on a decision. Use the [template](0000-template.md). Once accepted,
ADR content is frozen — write a new ADR to supersede.

Other repos maintain their own ADRs:

- [studio-ui](https://github.com/complytime-labs/studio-ui/tree/main/docs/decisions) — UI/UX patterns
- [complytime-studio](https://github.com/complytime-labs/complytime-studio/tree/main/docs/decisions) — agent and workbench
- [studio-deploy](https://github.com/complytime-labs/studio-deploy/tree/main/docs/decisions) — deployment and infra

## Active

| # | Decision | Status | Date |
|:--|:--|:--|:--|
| 0001 | [PostgreSQL as Primary Persistence Layer](postgres-with-extensions.md) | Accepted | 2026-05-01 |
| 0002 | [Migrate Gateway to Echo Framework](echo-framework-migration.md) | Accepted | 2026-05-01 |
| 0007 | [Default Admin & Token Hardening](default-admin-token-hardening.md) | Accepted | 2026-04-25 |
| 0008 | [Query Limit Cap](query-limit-cap.md) | Accepted | 2026-04-25 |
| 0009 | [Gemara-Native Security Development Lifecycle](gemara-native-sdlc.md) | Accepted | 2026-04-25 |
| 0010 | [OTel Collector Is Environment Infrastructure](otel-collector-out-of-chart.md) | Accepted | 2026-04-18 |
| 0014 | [Evidence Staleness Model](evidence-staleness-model.md) | Accepted | 2026-04-26 |
| 0016 | [PII in Structured Logs](pii-in-logs.md) | Accepted (revisit at RACI Phase 3) | 2026-04-27 |
| 0025 | [Data Platform + Workbench Split](data-platform-workbench-split.md) | Accepted | 2026-05-13 |
| 0027 | [JWT Bearer Authentication for Headless API Access](jwt-bearer-headless-auth.md) | Accepted | 2026-05-13 |
| 0028 | [Async Evidence Ingest: Accept-the-Loss Durability](async-ingest-durability.md) | Superseded by #0040 | 2026-05-13 |
| 0040 | [JetStream Durable Consumer for Ingest Pipeline](jetstream-ingest-consumer.md) | Accepted | 2026-05-28 |
| 0031 | [Three-Protocol Serving Layer](serving-layer-protocols.md) | Accepted | 2026-05-15 |
| 0033 | [Evidence Quality Boundary](evidence-quality-boundary.md) | Accepted | 2026-05-15 |
| 0034 | [Unified Ingest Pipeline](unified-ingest-pipeline.md) | Accepted | 2026-05-16 |
| 0035 | [Native FIPS 140-3 Build Support](fips-140-native.md) | Accepted | 2026-05-27 |
| 0036 | [Transparency Ledger (Tessera)](transparency-ledger.md) | Accepted | 2026-05-22 |
| 0037 | [Content Verification Service](content-verification-service.md) | Accepted | 2026-05-23 |
| 0038 | [Policy Enrollment and Discovery](policy-enrollment.md) | Accepted | 2026-05-26 |
| 0039 | [OCI Import Through Tessera](import-through-tessera.md) | Accepted | 2026-05-26 |
| 0040 | [Trust Signals Replace Binary Certified Flag](trust-signals-certification.md) | Accepted | 2026-06-01 |
| 0041 | [Anti-Equivocation Witnessing](anti-equivocation-witnessing.md) | Accepted | 2026-06-18 |
| 0042 | [Content Verification Service](content-verification-service.md) | Accepted | 2026-05-23 |
| 0043 | [Public API Boundary](public-api-boundary.md) | Accepted | 2026-06-19 |
| 0044 | [Remove PostgreSQL — ComplyTime Ingest](remove-postgresql.md) | Accepted | 2026-06-19 |

## Active Workarounds

| # | Decision | Status | Date |
|:--|:--|:--|:--|
| 0018 | [Gemara MCP Session Initialization Failures](gemara-mcp-session-failures.md) | Active workaround | 2026-04-18 |

## Superseded

| # | Decision | Status | Date |
|:--|:--|:--|:--|
| 0003 | [Modulith Gateway Architecture](backend-architecture.md) | Superseded by #0025 | 2026-04-18 |
| 0006 | [Internal Endpoint Isolation — Dual-Port Gateway](internal-endpoint-isolation.md) | Superseded | 2026-04-25 |
| 0026 | [ConnectRPC Internal API for complytime-mcp](connectrpc-internal-api.md) | Superseded | 2026-05-13 |

## Deferred

| Decision | Status |
|:--|:--|
| [External Authorization Engine](external-authz-engine.md) | Deferred — evaluate at RACI Phase 3 |

## Superseded by Implementation

| Decision | Superseded by |
|:--|:--|
| [Audit Provenance (hash chains)](audit-provenance-deferred.md) | #0036 Transparency Ledger (Tessera) |

## Exploratory

| Decision | Summary |
|:--|:--|
| [OTel-Native Ingestion](otel-native-ingestion.md) | Evidence flows through OTel Collector to storage |
| [Impact Graph](impact-graph.md) | Control failure blast radius via mapping_entries join |
| [Procedure Compliance: BPMN and Gemara](procedure-compliance-coverage.md) | BPMN proves via execution; Gemara via evidence |
| [Cloud-Native Posture Correction](cloud-native-posture-correction.md) | Event-driven ingestion, summary-only sovereignty |
| [Enforcement Log Traceability](enforcement-log-traceability.md) | Link EnforcementLogs to EvaluationLog findings |
