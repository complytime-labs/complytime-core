# Policy Enrollment and Discovery System

**Date**: 2026-05-26  
**Status**: Approved  
**Related**: Tessera Evidence Ingestion (2026-05-22)

## Overview

Enable publishers to discover which Gemara Policy artifacts apply to their targets based on multi-dimensional matching. When new policies are submitted to Tessera, publishers are notified and can query to find applicable policies for their evidence submissions.

## Problem Statement

**Current state**: Publishers hardcode policy references (`tessera-log-index: 42`) in their EvaluationLog YAML based on out-of-band communication (Slack, email, documentation).

**Problems this creates**:
1. **Discovery gap**: Teams don't know which policies exist in the system
2. **Applicability gap**: Teams don't know which policies apply to their specific targets
3. **Change blindness**: Teams miss when new policies are submitted or existing policies are updated

**Impact**: Publishers submit evidence with wrong policy references or miss policies entirely, breaking the compliance audit trail.

## Goals

1. **Target registration**: Publishers declare their targets with dimensional metadata (technologies, geopolitical regions, sensitivity levels)
2. **Policy discovery**: Publishers can query which policies apply to a specific target at a specific timestamp
3. **Change notification**: Publishers are notified when new policies are submitted to Tessera
4. **Dimension-based matching**: Policies and targets match when their dimension arrays have overlapping values
5. **Temporal correctness**: Policy matching respects `evaluation_timeline` - evidence timestamp determines applicable policy version

## Non-Goals

1. **Complex registry service** - Defer building a dedicated policy registry; gateway handles queries
2. **Targeted notifications** - Defer `core.policy.applicable.{target_id}` events; use broadcast `core.policy.new` only
3. **Webhook delivery** - Defer HTTP webhook notifications; NATS subscriptions only
4. **Strict witness validation** - Defer enforcing dimension matching in witness; log warnings only
5. **Policy recommendations** - Defer suggesting policies for similar targets
6. **Compliance dashboard UI** - Defer visual policy/target mapping interface

## Architecture

### Components

```
TargetRegistration (CUE) → /api/ingest → Tessera → Worker → PostgreSQL targets table
                                                            ↓
                                                    NATS core.target.registered

Policy → /api/ingest → Tessera → Worker → PostgreSQL policies table
                                         ↓
                                 NATS core.policy.new

Publisher queries: GET /api/policies?target_id=X&timestamp=Y
                        ↓
                   Gateway → PostgreSQL dimension matching
```

### Data Flow

1. **Publisher registers target**:
   - Submit `TargetRegistration` YAML via `/api/ingest` with JWT auth
   - Gateway appends to Tessera → returns `log_index`
   - Worker parses dimensions, inserts into `targets` table
   - Worker publishes `core.target.registered` event

2. **Compliance team submits policy**:
   - Submit `Policy` YAML via `/api/ingest` (existing flow)
   - Worker publishes `core.policy.new` event (new)

3. **Publisher discovers policies**:
   - Subscribe to `core.policy.new` NATS subject (get notified of all new policies)
   - Query `GET /api/policies?target_id=prod-cluster&timestamp=2026-05-26`
   - Response includes policies where:
     - Target dimensions overlap with policy dimensions
     - Timestamp falls within policy's `evaluation_timeline`

4. **Publisher submits evidence**:
   - Reference discovered policy `log_index` in `EvaluationLog.metadata.mapping-references`
   - Witness verifies policy reference exists (existing behavior)
   - Witness logs warning if dimensions don't match (advisory, non-blocking)

## Detailed Design

### 1. TargetRegistration CUE Extension

**Schema** (reuses Gemara base types):

```cue
// Extend artifact type enum
#ArtifactType: "Policy" | "EvaluationLog" | "EnforcementLog" | "AuditLog" | "TargetRegistration"

TargetRegistration: {
    metadata: #Metadata & {
        type: "TargetRegistration"
    }
    target: #Target
    dimensions: #Dimensions  // Same type as Policy dimensions
}
```

**Example YAML**:

```yaml
metadata:
  type: TargetRegistration
  id: prod-cluster-reg-v1
  version: 1.0.0
  date: "2026-05-26T10:00:00Z"
  author:
    name: platform-team

target:
  id: prod-cluster
  name: Production Kubernetes Cluster
  type: kubernetes-cluster

dimensions:
  technologies:
    - kubernetes
    - postgresql
  geopolitical:
    - EU
  sensitivity:
    - confidential
```

**Submission flow**:
- Publisher: `POST /api/ingest` with TargetRegistration YAML + JWT
- Gateway: Verifies JWT, appends to Tessera, returns `{log_index, job_id}`
- Worker: Parses YAML, inserts into `targets` table

### 2. Database Schema

**New table**:

```sql
CREATE TABLE IF NOT EXISTS targets (
    target_id           TEXT NOT NULL,
    tessera_log_index   BIGINT NOT NULL,
    target_name         TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    technologies        TEXT[] NOT NULL DEFAULT '{}',
    geopolitical        TEXT[] NOT NULL DEFAULT '{}',
    sensitivity         TEXT[] NOT NULL DEFAULT '{}',
    users               TEXT[] NOT NULL DEFAULT '{}',
    groups              TEXT[] NOT NULL DEFAULT '{}',
    registered_at       TIMESTAMPTZ NOT NULL,
    registered_by       TEXT NOT NULL,  -- JWT sub claim
    
    PRIMARY KEY (target_id, tessera_log_index)
);

CREATE INDEX idx_targets_registered_at ON targets(target_id, registered_at DESC);

-- GIN index for dimension overlap queries
CREATE INDEX idx_targets_dimensions ON targets USING GIN (
    technologies || geopolitical || sensitivity || users || groups
);
```

**Key design points**:
- **Append-only**: Compound primary key `(target_id, tessera_log_index)` allows multiple registrations per target
- **Temporal queries**: Latest registration as of timestamp uses `registered_at DESC` index
- **Dimension search**: GIN index enables efficient array overlap queries
- **Provenance**: `registered_by` tracks which JWT subject submitted the registration

**Worker processing**:

```go
// In ingest_worker.go, add case for TargetRegistration
case gemara.TargetRegistrationArtifact:
    handleTargetRegistration(ctx, evt, stores.Targets, pub, tracker)

func handleTargetRegistration(ctx, evt, targetStore, pub, tracker) {
    var reg TargetRegistration
    yaml.Unmarshal(evt.YAML, &reg)
    
    // Insert into targets table
    targetStore.InsertTarget(ctx, TargetRow{
        TargetID:        reg.Target.ID,
        TesseraLogIndex: evt.LogIndex,
        TargetName:      reg.Target.Name,
        TargetType:      reg.Target.Type,
        Technologies:    reg.Dimensions.Technologies,
        Geopolitical:    reg.Dimensions.Geopolitical,
        Sensitivity:     reg.Dimensions.Sensitivity,
        Users:           reg.Dimensions.Users,
        Groups:          reg.Dimensions.Groups,
        RegisteredAt:    reg.Metadata.Date,
        RegisteredBy:    evt.PublisherIdentity.Sub,
    })
    
    // Publish NATS event
    pub.PublishTargetRegistered(reg.Target.ID, evt.LogIndex)
}
```

### 3. Policy Query API

**New endpoint**: `GET /api/policies?target_id={id}&timestamp={iso8601}`

**Example request**:
```
GET /api/policies?target_id=prod-cluster&timestamp=2026-05-26T10:00:00Z
```

**Response**:
```json
{
  "target": {
    "id": "prod-cluster",
    "name": "Production Kubernetes Cluster",
    "type": "kubernetes-cluster",
    "dimensions": {
      "technologies": ["kubernetes", "postgresql"],
      "geopolitical": ["EU"],
      "sensitivity": ["confidential"]
    },
    "registered_at": "2026-05-01T00:00:00Z",
    "tessera_log_index": 15
  },
  "applicable_policies": [
    {
      "log_index": 42,
      "policy_id": "infra-security-baseline",
      "title": "Infrastructure Security Baseline Q2 2026",
      "version": "2.0.0",
      "evaluation_timeline": {
        "start": "2026-04-01T00:00:00Z",
        "end": "2026-06-30T23:59:59Z"
      },
      "enforcement_timeline": {
        "start": "2026-05-01T00:00:00Z"
      },
      "matching_dimensions": {
        "technologies": ["kubernetes"],
        "geopolitical": ["EU"]
      }
    }
  ]
}
```

**Matching algorithm**:

1. **Lookup target dimensions** (as of timestamp):
   ```sql
   SELECT * FROM targets 
   WHERE target_id = $1 
     AND registered_at <= $2
   ORDER BY registered_at DESC
   LIMIT 1
   ```

2. **Find policies with overlapping dimensions** (any dimension array has common elements):
   ```sql
   SELECT p.log_index, p.policy_id, p.content
   FROM policies p
   WHERE (
       p.technologies && $1  -- Array overlap operator
       OR p.geopolitical && $2
       OR p.sensitivity && $3
       OR p.users && $4
       OR p.groups && $5
   )
   AND p.evaluation_timeline_start <= $6
   AND p.evaluation_timeline_end >= $6
   ORDER BY p.log_index ASC
   ```

3. **Parse policy YAML to extract metadata** for response

**Implementation location**: `internal/store/handlers_policies.go` (new file)

### 4. NATS Events

**New subjects**:

```
core.policy.new           - Published when Policy artifact ingested (broadcast)
core.target.registered    - Published when TargetRegistration ingested
```

**Event schemas** (add to `internal/events/nats.go`):

```go
type PolicyEvent struct {
    LogIndex  uint64    `json:"log_index"`
    PolicyID  string    `json:"policy_id"`
    Timestamp time.Time `json:"timestamp"`
}

type TargetRegisteredEvent struct {
    LogIndex     uint64    `json:"log_index"`
    TargetID     string    `json:"target_id"`
    RegisteredBy string    `json:"registered_by"`
    Timestamp    time.Time `json:"timestamp"`
}

func (b *Bus) PublishPolicyNew(logIndex uint64, policyID string) {
    // Similar to PublishEvidence
}

func (b *Bus) PublishTargetRegistered(targetID string, logIndex uint64) {
    // Similar to PublishEvidence
}
```

**Worker modifications** (in `ingest_worker.go`):

```go
case gemara.PolicyArtifact:
    handleArtifactStore(evt, tracker, func() (string, string, error) {
        art, err := storePolicyFromContent(ctx, stores.Policies, stores.Controls, string(evt.YAML))
        
        // NEW: Publish policy event
        if err == nil && pub != nil {
            pub.PublishPolicyNew(evt.LogIndex, art.ID)
        }
        
        return art.ID, art.Type, err
    })
```

### 5. Publisher Integration

**One-time setup**:

1. **Register target**:
   ```bash
   # Create TargetRegistration YAML
   cat > target-registration.yaml <<EOF
   metadata:
     type: TargetRegistration
     id: prod-cluster-reg-v1
     version: 1.0.0
     date: "2026-05-26T10:00:00Z"
     author:
       name: platform-team
   target:
     id: prod-cluster
     name: Production K8s Cluster
     type: kubernetes-cluster
   dimensions:
     technologies: [kubernetes, postgresql]
     geopolitical: [EU]
     sensitivity: [confidential]
   EOF
   
   # Submit with JWT
   curl -X POST https://gateway/api/ingest \
     -H "Authorization: Bearer $JWT_TOKEN" \
     -H "Content-Type: application/x-yaml" \
     --data-binary @target-registration.yaml
   ```

2. **Subscribe to policy notifications** (optional):
   ```go
   // In publisher's service
   nc, _ := nats.Connect(natsURL)
   nc.Subscribe("core.policy.new", func(msg *nats.Msg) {
       var evt PolicyEvent
       json.Unmarshal(msg.Data, &evt)
       log.Printf("New policy available at log_index=%d", evt.LogIndex)
       
       // Trigger policy re-query
       queryApplicablePolicies()
   })
   ```

**Before each evidence submission**:

3. **Query applicable policies**:
   ```bash
   curl "https://gateway/api/policies?target_id=prod-cluster&timestamp=$(date -Iseconds)"
   ```

4. **Reference policies in evidence**:
   ```yaml
   metadata:
     type: EvaluationLog
     mapping-references:
       - id: infra-security-baseline
         tessera-log-index: 42  # From query response
   target:
     id: prod-cluster
   evaluations:
     - control: {...}
   ```

### 6. Witness Updates

**Advisory validation** (log warnings, don't reject):

When witness verifies `EvaluationLog` or `EnforcementLog`:

1. **Check target exists**:
   ```go
   targetExists := db.TargetExists(ctx, evidence.TargetID)
   if !targetExists {
       slog.Warn("evidence references unregistered target",
           "log_index", logIndex,
           "target_id", evidence.TargetID)
       // Continue verification (advisory warning only)
   }
   ```

2. **Check dimension match**:
   ```go
   targetDims := db.GetTargetDimensions(ctx, evidence.TargetID, evidence.Timestamp)
   policyDims := parsePolicyDimensions(policyEntry)
   
   if !dimensionsOverlap(targetDims, policyDims) {
       slog.Warn("policy dimensions don't match target",
           "log_index", logIndex,
           "target_id", evidence.TargetID,
           "policy_index", policyIndex)
       // Continue verification (advisory warning only)
   }
   ```

**Rationale for advisory-only**:
- Allows gradual adoption - teams can start using the system without breaking existing flows
- Witness logs provide visibility into dimension mismatches for auditing
- Can switch to strict enforcement later once all teams are enrolled

**Trusted publisher config** (add TargetRegistration to allowed types):

```yaml
# deploy/k8s/witness-config.yaml
witness:
  name: internal-compliance-witness

trusted_publishers:
  - name: platform-infrastructure
    issuer: https://token.actions.githubusercontent.com
    sub: "repo:org/infrastructure/*"
    allowed_types: [TargetRegistration, EvaluationLog, EnforcementLog]
  
  - name: k8s-admission-controllers
    issuer: https://kubernetes.default.svc
    sub: "system:serviceaccount:policy-system:*"
    allowed_types: [TargetRegistration, EnforcementLog]
```

## Implementation Notes

### Policy Storage

**Assumption**: Existing `policies` table needs dimension columns added:

```sql
-- Migration: Add dimension columns to policies table
ALTER TABLE policies ADD COLUMN IF NOT EXISTS technologies TEXT[] DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS geopolitical TEXT[] DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS sensitivity TEXT[] DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS users TEXT[] DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS groups TEXT[] DEFAULT '{}';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_start TIMESTAMPTZ;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS evaluation_timeline_end TIMESTAMPTZ;

CREATE INDEX idx_policies_dimensions ON policies USING GIN (
    technologies || geopolitical || sensitivity || users || groups
);
```

**Worker modification**: When parsing Policy YAML, extract dimensions and timeline for PostgreSQL storage.

### Error Handling

**Target not found**:
- Query returns `{"error": "target not found", "target_id": "unknown"}`
- Publisher should register target first

**No applicable policies**:
- Query returns `{"target": {...}, "applicable_policies": []}`
- Valid state - target may not have compliance requirements yet

**Timestamp in future**:
- Query returns policies with `evaluation_timeline.start <= timestamp`
- Allows pre-planning for upcoming evaluation windows

## Testing Strategy

1. **Unit tests**:
   - Dimension overlap logic
   - Temporal filtering (timestamp within evaluation_timeline)
   - NATS event publishing

2. **Integration tests**:
   - Submit TargetRegistration → verify `targets` table
   - Submit Policy → verify `core.policy.new` event
   - Query API → verify correct policies returned
   - Submit evidence → witness logs advisory warnings

3. **E2E scenarios**:
   - Publisher registers target with kubernetes dimension
   - Compliance submits policy requiring kubernetes
   - Publisher queries and finds policy
   - Publisher submits evidence referencing policy
   - Witness verifies successfully

## Future Enhancements (Deferred)

### Policy Registry Service

Dedicated microservice that:
- Maintains in-memory policy index for fast lookups
- Publishes `core.policy.applicable.{target_id}` targeted events
- Handles complex matching rules (policy inheritance, exclusions)

**When to build**: When query latency becomes a bottleneck (>100ms) or we have >1000 active policies.

### Webhook Notifications

Allow publishers to register webhook URLs for policy notifications instead of running NATS subscribers.

**When to build**: When teams without NATS infrastructure need notifications.

### Strict Witness Validation

Enforce dimension matching in witness - reject evidence where target/policy dimensions don't overlap.

**When to build**: After 90% of publishers have registered targets (measured via witness logs).

### Policy Recommendations

Suggest policies for newly registered targets based on similar targets' policy assignments.

**When to build**: When we have >50 targets and patterns emerge.

### Compliance Dashboard

UI showing:
- All targets and their dimensions
- All policies and their applicability
- Coverage gaps (targets without policies)
- Drift detection (evidence submitted without applicable policies)

**When to build**: When compliance team needs visual policy management (not just API).

## Migration Path

**Existing publishers** (pre-enrollment system):
1. Continue submitting evidence with hardcoded policy references
2. Witness logs advisory warnings about unregistered targets
3. Teams gradually register targets as they update infrastructure

**New publishers**:
1. Must register targets before submitting evidence
2. Use policy query API to discover applicable policies
3. Subscribe to `core.policy.new` for notifications

**No breaking changes** - system is additive, existing flows continue working.
