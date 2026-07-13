# Policy Enrollment and Discovery

**Status:** Accepted
**Date:** 2026-05-26

## Decision

Publishers register targets with dimensional metadata via a `TargetRegistration` artifact (CUE extension to Gemara). A policy discovery API matches targets to policies by dimension overlap and evaluation timeline. NATS events broadcast new policy and target registration events. The gateway handles discovery queries directly against PostgreSQL — no dedicated registry service.

## Context

Publishers need to know which Gemara Policy artifacts apply to their targets before submitting evidence. Without enrollment, publishers hardcode policy references based on out-of-band communication (Slack, email, documentation). This creates three problems:

1. **Discovery gap** — teams don't know which policies exist
2. **Applicability gap** — teams don't know which policies apply to their specific targets
3. **Change blindness** — teams miss new policies

## How It Works

**Target registration:** Publishers submit a `TargetRegistration` artifact via `/api/ingest` containing target metadata and dimensional criteria (technologies, geopolitical, sensitivity, users, groups). These dimensions match the `#Dimensions` type from Gemara's Policy `scope.in` field.

**Policy discovery:** `GET /api/policies/discover?target_id=X&timestamp=Y` finds the target's latest dimensions, queries policies where any dimension array overlaps (PostgreSQL `&&` operator), and filters by evaluation_timeline. Returns matching policies with their tessera_log_index for evidence references.

**Notifications:** Worker publishes `core.policy.new` when policies are ingested and `core.target.registered` when targets are registered. Publishers subscribe to these NATS subjects for awareness.

## Why TargetRegistration as a CUE Extension

Gemara's `metadata.type` enum is closed. `TargetRegistration` is not a standard Gemara artifact — it's a platform-specific extension. The ingest worker falls back to string-based type detection when `go-gemara`'s `DetectType` returns an error, handling CUE extensions without requiring upstream library changes.

## Why Not a Dedicated Registry Service

A separate policy registry microservice was considered and rejected for MVP. The gateway queries PostgreSQL directly using array overlap operators and timeline filtering. This adds two SQL queries, not a new service. A registry service becomes justified if query latency exceeds 100ms or policy count exceeds 1000.

## Why Append-Only Targets

Target registrations are append-only (compound primary key: `target_id + tessera_log_index`). This provides an audit trail of dimension changes — when a cluster started handling PII, when it moved to EU jurisdiction. Policy queries use the most recent registration as of the evidence timestamp, preventing retroactive dimension manipulation.

## Coverage Gap Detection

The enrollment system enables coverage gap detection: complytime-core knows what evidence it **should** receive (targets registered with applicable policies) vs what it **has** received. This is the key value beyond advisory policy discovery.

## Alternatives Considered

| Alternative | Why not |
|:--|:--|
| Admin-driven policy assignment | Doesn't scale; compliance team becomes bottleneck |
| Publisher pattern matching only | Ignores target-specific dimensions (geopolitical, sensitivity) |
| Dedicated registry service | Over-engineered for current scale; gateway queries are sufficient |
| Webhook notifications | NATS subscriptions are sufficient; webhooks add delivery infrastructure |
| Strict witness enforcement | Advisory first to allow gradual enrollment adoption |

## Related

- [Transparency Ledger](transparency-ledger.md) — TargetRegistrations flow through Tessera
- [Content Verification Service](content-verification-service.md) — advisory validation for unregistered targets
- [Unified Ingest Pipeline](unified-ingest-pipeline.md) — all artifacts route through same pipeline
