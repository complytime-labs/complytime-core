<!-- SPDX-License-Identifier: Apache-2.0 -->

# Service Level Requirements

Requirements for the compliance data platform and agent workbench, derived from the initial deployment model and co-engineering integration strategy.

---

## 1. Integration and Interoperability

| Requirement | Owner | Gap Status | References |
|:--|:--|:--|:--|
| Cluster management observability integration — correlate compliance results with cluster-level observability data | Workbench | Not started | -- |
| Cross-framework mapping — translate technical evidence across regulatory frameworks via standardized interchange formats | Data Platform | Partial | Mapping store exists (`mapping_entries` table). No framework-specific content seeded beyond initial catalogs |
| Plugin architecture — support hot-swap addition of compliance plugins for different managed infrastructure stacks | Workbench | Partial | A2A protocol provides the plugin interface. Deploying a new agent = adding a plugin |

## 2. Data Handling and Transport

| Requirement | Owner | Gap Status | References |
|:--|:--|:--|:--|
| Evidence collection pipeline — high-volume transport of evidence from edge nodes/clusters to central storage via OpenTelemetry | Data Platform | Partial | ADRs accepted: collector is operator-managed infrastructure, evidence flows through collector exporters directly to storage. `POST /api/ingest` exists as fallback | [otel-native-ingestion](../decisions/otel-native-ingestion.md), [otel-collector-out-of-chart](../decisions/otel-collector-out-of-chart.md) |
| Attestation locker — centralized verifiable record of compliance evidence with timestamped storage | Data Platform | Exists | Tessera transparency log provides append-only, tamper-evident storage with cryptographic ordering. Independent witness service verifies entries. PostgreSQL caches queryable data with `log_index` linking to Tessera entries | [transparency-ledger](../decisions/transparency-ledger.md), [witness-service](../decisions/witness-service.md) |
| Standardized output — programmatic generation of artifacts in Gemara and OSCAL formats on demand | Data Platform | Partial | Gemara output exists (validate, publish). OSCAL generation not implemented | -- |

## 3. Connectivity and Availability

| Requirement | Owner | Gap Status | References |
|:--|:--|:--|:--|
| Programmatic API access — REST API designed for high availability (99.9% target) to ensure external GRC tools can always fetch compliance state | Data Platform | Partial | Full REST API exists. No HA configuration (PDB, HPA, multi-replica). Single-replica default | -- |
| Automated scanning schedule — support triggered and scheduled scans via configuration management tooling to ensure evidence currency | Workbench | Not started | No scheduling system. Agent invocation is manual via UI | -- |

## 4. Security and Compliance

| Requirement | Owner | Gap Status | References |
|:--|:--|:--|:--|
| Evidence integrity — stored evidence is immutable and timestamped, providing chain of custody for auditors | Data Platform | Exists | Tessera transparency log (Trillian successor) provides immutable, append-only storage with witness-countersigned checkpoints. JWT-verified publisher identity tracked for provenance | [transparency-ledger](../decisions/transparency-ledger.md), [witness-service](../decisions/witness-service.md) |
| Content ingestion — pull updated compliance content (rules, checks, catalogs) from OCI-compliant registries to scan against latest regulatory definitions | Data Platform | Exists | Unified ingest pipeline: seed jobs submit artifacts via `POST /api/ingest`; no periodic background refresh documented | -- |

---

## Gap Summary

| Status | Count |
|:--|:--|
| Exists | 3 |
| Partial | 4 |
| Not started | 2 |

## Priority Gaps

1. **OSCAL output** — no OSCAL generation capability. Required for cross-tool interoperability.
2. **Automated scanning** — no scheduling. Required for evidence freshness guarantees.
3. **HA/availability** — single replica default. Required for 99.9% SLA.
