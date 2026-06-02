# Stratified Trust Layers Architecture

**Date:** 2026-05-29  
**Status:** Draft  
**Authors:** Jennifer Power, Claude Sonnet 4.5

## Executive Summary

Replace the current binary `certified` flag and duplicated trust verification logic with a three-layer architecture that provides queryable trust signals, target-scoped publisher authorization, and cryptographically signed attestations for external verification.

**Business Value:**
- **Compliance:** Satisfies NIST 800-53 Rev 5 controls required for FedRAMP High (CM-14, SI-7(15), AU-9, AU-10, SR-3, SR-4)
- **Security:** Closes NATS publisher identity gap, prevents unauthorized evidence submission
- **Auditability:** Queryable trust signals ("show me evidence where freshness failed but everything else passed")
- **Federation:** External parties can cryptographically verify evidence authenticity

**Key Principle:** No features without clear business value. This architecture addresses real security gaps (NATS spoofing, global publisher authorization) and compliance requirements (immutable audit trail, provenance), not theoretical concerns.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Current Architecture Issues](#current-architecture-issues)
3. [Proposed Architecture](#proposed-architecture)
4. [Layer 1: Identity](#layer-1-identity)
5. [Layer 2: Quality](#layer-2-quality)
6. [Layer 3: Attestation](#layer-3-attestation)
7. [Database Schema](#database-schema)
8. [Gemara Artifacts](#gemara-artifacts)
9. [NIST 800-53 Mapping](#nist-800-53-mapping)
10. [Migration Path](#migration-path)
11. [Implementation Issues](#implementation-issues)

---

## Problem Statement

**What attacks or failure modes are we trying to prevent?**

1. **NATS payload spoofing:** Ingest worker trusts `PublisherIdentity` from NATS message instead of re-deriving from Tessera (Issue #37)
2. **Unauthorized publishers:** ANY globally trusted publisher can submit evidence for ANY target (no target-scoped authorization)
3. **Opaque trust decisions:** Binary `certified` flag doesn't explain WHY evidence failed (schema? freshness? unauthorized publisher?)
4. **No external verification:** Auditors can't cryptographically verify evidence came from our system
5. **Duplicate verification logic:** Publisher trust checked in both witness service AND (planned) certifier pipeline

**What compliance requirements must we meet?**

FedRAMP High requires NIST 800-53 High Impact Baseline controls:
- **CM-14:** Signed components (cryptographic publisher verification)
- **SI-7(15):** Code authentication (OIDC JWT validation)
- **AU-9(3):** Cryptographic protection of audit information (witness signatures)
- **AU-10:** Non-repudiation (immutable audit trail)
- **SR-4:** Software provenance (publisher identity in Tessera)
- **AC-6:** Least privilege (target-scoped authorization, not global)

---

## Current Architecture Issues

### Issue 1: Duplication
Publisher trust is verified in:
- Witness service (`isPublisherTrusted()` in `cmd/witness/verifier.go`)
- Planned: PublisherCertifier in ingest worker pipeline

**Root cause:** Unclear separation of responsibilities. Is the witness "independent audit" or "the actual trust boundary"?

### Issue 2: Separation
Certifiers run in ingest worker, but publisher verification happens in witness service after the fact. Evidence appears in PostgreSQL before witness verifies it.

**Root cause:** Two-phase verification (optimistic ingest, eventual verification) adds complexity without clear benefit.

### Issue 3: NATS Trust Gap
`PublisherIdentity` flows through NATS payload. If NATS is compromised, attacker can forge publisher identity by publishing crafted messages to `core.ingest`.

**Root cause:** Worker trusts NATS payload instead of re-deriving from Tessera (source of truth).

### Issue 4: Abstraction Mismatch
Publisher verification, schema validation, provenance checks, and freshness checks are all "certifiers" but they're fundamentally different concerns:
- **Publisher verification** = identity/authorization (Layer 1 concern)
- **Schema validation** = data quality (Layer 2 concern)
- **Witness countersigning** = attestation for external parties (Layer 3 concern)

**Root cause:** Treating everything as a "certifier" when they serve different purposes.

### Issue 5: Binary Trust Signal
`evidence.certified = true/false` doesn't explain:
- Which checks passed/failed
- Why evidence was rejected
- When verification happened

**Root cause:** No queryable trust signals. Can't filter by "show me evidence where freshness failed."

---

## Proposed Architecture

### Three Independent Trust Layers

Each layer has a clear purpose and responsibility:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: IDENTITY (HTTP Ingest)                            │
│ Purpose: Cryptographic proof of publisher identity         │
│ Validates: JWT signature, issuer, subject                  │
│ Writes to: Tessera (immutable log with identity metadata)  │
│ NIST Controls: CM-14, SI-7(15), SR-4                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: QUALITY (Ingest Worker via NATS)                  │
│ Purpose: Evidence meets business quality standards         │
│ Validates: Publisher authorized for target, schema,        │
│            provenance, executor, freshness, relevance       │
│ Re-derives: Publisher identity from Tessera (NATS carries  │
│             only log_index - no trust payload)              │
│ Writes to: PostgreSQL evidence + trust_signals             │
│ NIST Controls: AC-3, AC-6, SR-3, SI-7                      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: ATTESTATION (Witness Service)                     │
│ Purpose: Independent verification + signed attestation     │
│ Validates: Publisher identity from Tessera (defense depth) │
│ Aggregates: Trust signals from Layer 2                     │
│ Signs: Certification bundle for external verification      │
│ Writes to: witness_certifications table                    │
│ NIST Controls: AU-9, AU-9(3), AU-10, SI-7(6)              │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**1. No more binary `certified` flag**
Replace with queryable trust signals: one row per check (publisher_auth, schema, freshness, etc.) in `trust_signals` table.

**2. Publisher identity is cryptographically committed to Tessera**
Layer 1 augments Gemara artifact with `metadata.publisher` after JWT verification. NATS payload only carries `log_index` (no identity claims).

**3. Target-scoped publisher authorization**
Each target defines which OIDC identities can submit evidence for it. Publishers can ONLY submit for targets they're authorized for (not global).

**4. Witness countersigning is for external verification**
Witness aggregates trust signals, signs certification bundle with persistent ES256 key. Signature proves "ComplyTime verified this evidence at time T" for external auditors/GRC platforms.

**5. Defense in depth**
Layer 2 re-derives publisher from Tessera (NATS can't be spoofed). Layer 3 independently re-verifies publisher (catches bugs/compromises in Layer 2).

---

## Layer 1: Identity

### Purpose
Cryptographic proof of publisher identity. Prevents unauthorized publishers from submitting evidence.

### Responsibilities
1. Validate JWT signature against OIDC provider JWKS
2. Extract publisher identity claims (`iss`, `sub`, `aud`)
3. Embed publisher metadata into Gemara artifact
4. Append to Tessera transparency log

### Flow

```
POST /api/ingest
Authorization: Bearer <JWT>
Body: <Gemara YAML>

↓

1. Parse JWT, verify signature (coreos/go-oidc)
   - Fetch JWKS from provider (cached)
   - Verify signature (RS256/ES256)
   - Check expiration, audience

2. Extract claims:
   iss: https://token.actions.githubusercontent.com
   sub: repo:acme/scanner:ref:refs/heads/main
   aud: complytime-core

3. Augment Gemara artifact with publisher metadata:
   metadata:
     publisher:
       issuer: <iss>
       subject: <sub>
       verified-at: <timestamp>

4. Append augmented YAML to Tessera (immutable log entry)

5. Return: log_index

6. Publish NATS event:
   {
     "job_id": "...",
     "log_index": 12345,  # ONLY the index, NO identity claims
     "yaml": <augmented artifact>
   }
```

### What Gets Stored in Tessera

```yaml
metadata:
  type: EvaluationLog
  id: eval-001
  date: "2026-05-29T10:00:00Z"
  
  # Added by Layer 1 after JWT verification
  publisher:
    issuer: https://token.actions.githubusercontent.com
    subject: repo:acme/scanner:ref:refs/heads/main
    verified-at: "2026-05-29T10:00:15Z"

target:
  id: arn:aws:eks:us-east-1:123:cluster/prod
  
results:
  - evidence-id: trivy-vuln-001
    # ... evidence data ...
```

### NIST 800-53 Controls

| Control | How Layer 1 Satisfies It |
|---------|--------------------------|
| **CM-14: Signed Components** | JWT signature verification validates publisher identity cryptographically before accepting evidence |
| **SI-7(15): Code Authentication** | OIDC JWT validation provides cryptographic proof of publisher identity (issuer + subject) |
| **SR-4: Provenance** | `metadata.publisher` embedded in Tessera entry creates immutable provenance record |

---

## Layer 2: Quality

### Purpose
Evidence meets business quality standards AND publisher is authorized for the specific target.

### Responsibilities
1. Re-derive publisher identity from Tessera (NATS gap closed)
2. Validate publisher is authorized for target (target-scoped)
3. Run quality checks (schema, provenance, executor, freshness, relevance)
4. Write trust signals to PostgreSQL

### Flow

```
NATS event received: {log_index: 12345}

↓

1. Read Tessera entry at log_index
2. Parse Gemara artifact
3. Extract publisher from metadata.publisher:
   issuer: https://token.actions.githubusercontent.com
   subject: repo:acme/scanner:ref:refs/heads/main

4. CHECK: Publisher authorization (NEW)
   a. Query latest TargetRegistration for target.id
   b. Match publisher (iss + sub) against trusted-publishers array
   c. Glob matching: repo:acme/scanner:* matches repo:acme/scanner:ref:refs/heads/main
   d. If NO match → FAIL "unauthorized publisher for target"
   e. Write trust_signal: publisher_auth = pass/fail

5. CHECK: Schema validation
   - Required fields present (evidence_id, target_id, rule_id, etc.)
   - Enum values valid (eval_result, compliance_status)
   - Timestamps sane (not future, not zero)
   - Write trust_signal: schema = pass/fail

6. CHECK: Provenance
   - source_registry OR attestation_ref exists
   - If source_registry present, validate against KNOWN_REGISTRIES
   - Write trust_signal: provenance = pass/fail

7. CHECK: Executor
   - engine_name present
   - engine_name in KNOWN_ENGINES allowlist
   - Write trust_signal: executor = pass/fail

8. CHECK: Freshness (policy-aware)
   - Query policy for requirement_id's assessment plan
   - Map frequency (daily/weekly/monthly) to cycle days
   - Compare collected_at age against cycle
   - on-demand = never stale
   - Fallback to 30-day default if no plan
   - Write trust_signal: freshness = pass/fail

9. CHECK: Relevance
   - Query policy for control_id
   - Query control for requirement_id
   - Verify evidence maps to valid policy requirement
   - Write trust_signal: relevance = pass/fail

10. Write evidence table (denormalized):
    evidence_id: eval-001
    certified: <aggregate of trust signals>
    submitted_by: repo:acme/scanner:ref:refs/heads/main
    publisher_issuer: https://token.actions.githubusercontent.com
    publisher_metadata: {issuer, subject, verified-at}
```

### Quality Validators

#### PublisherAuthorizationValidator

**Purpose:** Ensure publisher (iss + sub) is authorized to submit evidence for this target.

```go
type PublisherAuthorizationValidator struct {
    TargetStore TargetStore
}

func (v *PublisherAuthorizationValidator) Check(ctx context.Context, row EvidenceRow) TrustSignal {
    // Get latest TargetRegistration
    target, err := v.TargetStore.GetLatestTarget(ctx, row.TargetID)
    if err != nil {
        return TrustSignal{
            Layer: "quality",
            Check: "publisher_auth",
            Result: "error",
            Reason: fmt.Sprintf("target not found: %v", err),
        }
    }
    
    // Match publisher against trusted publishers
    for _, pub := range target.TrustedPublishers {
        if pub.Issuer != row.PublisherIssuer {
            continue
        }
        
        // Glob matching on sub pattern
        if matchGlob(pub.SubPattern, row.SubmittedBy) {
            return TrustSignal{
                Layer: "quality",
                Check: "publisher_auth",
                Result: "pass",
                Reason: fmt.Sprintf("matched %s:%s", pub.Issuer, pub.SubPattern),
            }
        }
    }
    
    return TrustSignal{
        Layer: "quality",
        Check: "publisher_auth",
        Result: "fail",
        Reason: "publisher not authorized for target",
    }
}
```

#### FreshnessValidator

**Purpose:** Policy-aware staleness check against assessment plan frequency.

```go
type FreshnessValidator struct {
    PolicyStore PolicyStore
}

func (v *FreshnessValidator) Check(ctx context.Context, row EvidenceRow) TrustSignal {
    policy, err := v.PolicyStore.GetPolicy(ctx, row.PolicyID)
    if err != nil {
        return TrustSignal{
            Layer: "quality",
            Check: "freshness",
            Result: "error",
            Reason: err.Error(),
        }
    }
    
    // Find assessment plan for this requirement
    plan := findAssessmentPlan(policy, row.RequirementID)
    if plan == nil {
        // Fallback to 30-day default
        if row.CollectedAt.Before(time.Now().Add(-30 * 24 * time.Hour)) {
            return TrustSignal{
                Layer: "quality",
                Check: "freshness",
                Result: "fail",
                Reason: "older than 30d default",
            }
        }
        return TrustSignal{
            Layer: "quality",
            Check: "freshness",
            Result: "pass",
            Reason: "within 30d default",
        }
    }
    
    // on-demand = never stale
    if plan.Frequency == "on-demand" {
        return TrustSignal{
            Layer: "quality",
            Check: "freshness",
            Result: "pass",
            Reason: "on-demand frequency",
        }
    }
    
    cycleDays := frequencyToDays(plan.Frequency)
    age := time.Since(row.CollectedAt)
    
    if age > time.Duration(cycleDays) * 24 * time.Hour {
        return TrustSignal{
            Layer: "quality",
            Check: "freshness",
            Result: "fail",
            Reason: fmt.Sprintf("age=%dd, frequency=%s (%dd cycle)", 
                int(age.Hours()/24), plan.Frequency, cycleDays),
        }
    }
    
    return TrustSignal{
        Layer: "quality",
            Check: "freshness",
        Result: "pass",
        Reason: fmt.Sprintf("age=%dd, frequency=%s (%dd cycle)",
            int(age.Hours()/24), plan.Frequency, cycleDays),
    }
}

func frequencyToDays(frequency string) int {
    switch frequency {
    case "daily": return 1
    case "weekly": return 7
    case "monthly": return 30
    case "quarterly": return 90
    case "annually": return 365
    default: return 30 // fallback
    }
}
```

#### RelevanceValidator

**Purpose:** Validate evidence maps to a valid control/requirement in its declared policy.

```go
type RelevanceValidator struct {
    PolicyStore PolicyStore
}

func (v *RelevanceValidator) Check(ctx context.Context, row EvidenceRow) TrustSignal {
    policy, err := v.PolicyStore.GetPolicy(ctx, row.PolicyID)
    if err != nil {
        return TrustSignal{
            Layer: "quality",
            Check: "relevance",
            Result: "error",
            Reason: err.Error(),
        }
    }
    
    // Check control_id exists
    control := findControl(policy, row.ControlID)
    if control == nil {
        return TrustSignal{
            Layer: "quality",
            Check: "relevance",
            Result: "fail",
            Reason: fmt.Sprintf("control_id %s not in policy", row.ControlID),
        }
    }
    
    // Check requirement_id exists under that control
    requirement := findRequirement(control, row.RequirementID)
    if requirement == nil {
        return TrustSignal{
            Layer: "quality",
            Check: "relevance",
            Result: "fail",
            Reason: fmt.Sprintf("requirement_id %s not under control %s", 
                row.RequirementID, row.ControlID),
        }
    }
    
    return TrustSignal{
        Layer: "quality",
        Check: "relevance",
        Result: "pass",
        Reason: "control and requirement exist in policy",
    }
}
```

### Target-Scoped Publisher Authorization

**Model:** Each target declares which OIDC identities are authorized to submit evidence for it.

**TargetRegistration Gemara artifact:**

```yaml
metadata:
  type: TargetRegistration
  id: target-reg-prod-eks-001
  date: "2026-05-29T10:00:00Z"

target:
  id: arn:aws:eks:us-east-1:123:cluster/prod-cluster
  technologies: [kubernetes, aws-eks]
  environment: [production]
  
  # Only these OIDC identities can submit evidence for this target
  trusted-publishers:
    # GitHub Actions workflow (with environment gate)
    - issuer: https://token.actions.githubusercontent.com
      repository: acme/compliance-scanner
      workflow: scan.yml
      environment: production  # Requires manual approval
    
    # Google Cloud service account
    - issuer: https://accounts.google.com
      sub: scanner-service@acme-prod.iam.gserviceaccount.com
    
    # GitLab CI pipeline
    - issuer: https://gitlab.com
      project-path: acme/security-scanner
      ref: main
      ref-type: branch
```

**Why target-scoped instead of global?**

1. **Least privilege (AC-6):** Scanners can ONLY submit for targets they're authorized for
2. **Prevents cross-target injection:** Compromised scanner for dev can't submit evidence for prod
3. **Organizational ownership:** Platform team can authorize different scanners per environment

**Authorization flow:**

```
Evidence JWT claims:
  iss: https://token.actions.githubusercontent.com
  sub: repo:acme/compliance-scanner:ref:refs/heads/main

Layer 2 checks:
  1. Read latest TargetRegistration for target_id
  2. Parse trusted-publishers array
  3. Match (iss, sub) against patterns
  4. Glob matching: repo:acme/compliance-scanner:* matches the sub
  5. Result: publisher_auth = pass
```

### NIST 800-53 Controls

| Control | How Layer 2 Satisfies It |
|---------|--------------------------|
| **AC-3: Access Enforcement** | Publisher authorization check enforces approved access (target-scoped, not global) |
| **AC-6: Least Privilege** | Publishers can ONLY submit for authorized targets (prevents cross-target injection) |
| **SR-3: Supply Chain Controls** | Quality validators (schema/provenance/executor) protect against supply chain risks |
| **SR-4(1): Provenance — Identity** | Re-derives publisher from Tessera (defense against NATS spoofing) |
| **SI-7: Software Integrity** | Freshness/relevance validators detect stale or orphaned evidence |

---

## Layer 3: Attestation

### Purpose
Independent verification + cryptographically signed attestation for external parties (auditors, GRC platforms).

### Responsibilities
1. Re-verify publisher identity from Tessera (defense in depth)
2. Aggregate trust signals from Layer 2
3. Sign certification bundle (Tessera entry + trust signals + timestamp)
4. Update `evidence.certified` based on aggregate result

### Flow

```
Witness polls Tessera for new entries

↓

1. Read entry at log_index
2. Parse Gemara artifact
3. Re-derive publisher from metadata.publisher (independent verification)

4. Query trust_signals for this evidence_id
   SELECT * FROM trust_signals WHERE evidence_id = 'eval-001'

5. Aggregate results:
   - Check ALL signals are "pass"
   - If ANY signal is "fail" → evidence.certified = false
   - If ALL signals are "pass" → proceed to signing

6. Build certification bundle:
   {
     "tessera_log_index": 12345,
     "evidence_id": "eval-001",
     "target_id": "arn:aws:eks:...",
     "publisher": {
       "issuer": "https://token.actions.githubusercontent.com",
       "subject": "repo:acme/scanner:ref:refs/heads/main"
     },
     "trust_signals": [
       {"layer": "identity", "check": "publisher_auth", "result": "pass", 
        "reason": "matched repo:acme/scanner:*", "checked_at": "2026-05-29T10:00:20Z"},
       {"layer": "quality", "check": "schema", "result": "pass",
        "reason": "all required fields present", "checked_at": "2026-05-29T10:00:21Z"},
       {"layer": "quality", "check": "freshness", "result": "pass",
        "reason": "age=2d, frequency=weekly (7d cycle)", "checked_at": "2026-05-29T10:00:22Z"},
       // ... all other signals ...
     ],
     "verified_at": "2026-05-29T10:05:00Z"
   }

7. Sign bundle with ES256 private key
   signature = sign(JSON.stringify(bundle), privateKey)

8. Write witness_certifications table:
   evidence_id: eval-001
   tessera_log_index: 12345
   certification_bundle: <bundle JSON>
   signature: <base64 ES256 signature>
   public_key_fingerprint: SHA256:abc123...
   signed_at: 2026-05-29T10:05:00Z

9. Update evidence.certified = true
```

### External Verification Flow

**Auditor requests certification:**

```
GET /api/evidence/eval-001/certification

Response:
{
  "evidence_id": "eval-001",
  "tessera_log_index": 12345,
  "certification": {
    "bundle": {
      "tessera_log_index": 12345,
      "evidence_id": "eval-001",
      "target_id": "arn:aws:eks:...",
      "publisher": {
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:acme/scanner:ref:refs/heads/main"
      },
      "trust_signals": [
        {"layer": "identity", "check": "publisher_auth", "result": "pass", ...},
        {"layer": "quality", "check": "schema", "result": "pass", ...},
        // ... all signals ...
      ],
      "verified_at": "2026-05-29T10:05:00Z"
    },
    "signature": "MEUCIQD...",  // Base64-encoded ES256 signature
    "public_key_fingerprint": "SHA256:abc123..."
  }
}
```

**Auditor verifies signature:**

```bash
# 1. Fetch ComplyTime's public key
curl https://complytime.example.com/.well-known/witness-public-key.pem > pubkey.pem

# 2. Extract bundle and signature from API response
cat response.json | jq -r '.certification.bundle' > bundle.json
cat response.json | jq -r '.certification.signature' | base64 -d > signature.bin

# 3. Verify signature
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin bundle.json

# Output: Verified OK
```

**What the signature proves:**
- This certification bundle was created by ComplyTime's witness service
- The bundle contents have not been tampered with since signing
- ComplyTime verified this evidence at the timestamp in `verified_at`
- All trust signals were "pass" at verification time

**What the signature does NOT prove:**
- That the evidence is still fresh (check `verified_at` timestamp)
- That the publisher's credentials weren't compromised (same limitation as Sigstore/npm)
- That the evidence is correct (signature proves verification happened, not correctness)

### Persistent Signing Key

**Current state:** Witness uses ephemeral keys (new key on each restart). Signatures can't be verified after restart.

**New design:** Persistent ES256 keypair stored in Kubernetes secret.

```yaml
# kubernetes/witness-signing-key-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: witness-signing-key
type: Opaque
data:
  private-key.pem: <base64-encoded ES256 private key>
  public-key.pem: <base64-encoded ES256 public key>
```

**Key rotation:**
- Generate new keypair
- Update secret
- Restart witness service
- Old signatures remain valid (public key fingerprint in certifications table)
- Publish current + previous public keys at `/.well-known/witness-public-keys.json`

### NIST 800-53 Controls

| Control | How Layer 3 Satisfies It |
|---------|--------------------------|
| **AU-9: Protection of Audit Information** | Tessera append-only log (WORM semantics), cryptographically linked Merkle tree |
| **AU-9(3): Cryptographic Protection** | Witness ES256 signatures protect integrity of certification bundles |
| **AU-10: Non-repudiation** | JWT (Layer 1) + Tessera immutability + witness signature = non-repudiable audit trail |
| **AU-11: Audit Record Retention** | Tessera entries + certifications table retained indefinitely |
| **SI-7(6): Cryptographic Protection** | Witness re-verifies publisher from Tessera (independent check), signs aggregate |

---

## Database Schema

### New Tables

#### trust_signals

**Purpose:** Queryable trust signals (replaces binary `certified` flag).

```sql
CREATE TABLE IF NOT EXISTS trust_signals (
    evidence_id       TEXT NOT NULL,
    layer             TEXT NOT NULL,  -- 'identity', 'quality', 'attestation'
    check_name        TEXT NOT NULL,  -- 'publisher_auth', 'schema', 'freshness', etc.
    result            TEXT NOT NULL,  -- 'pass', 'fail', 'skip', 'error'
    reason            TEXT NOT NULL DEFAULT '',
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    PRIMARY KEY (evidence_id, layer, check_name),
    
    CONSTRAINT trust_signals_layer_chk CHECK (
        layer IN ('identity', 'quality', 'attestation')
    ),
    CONSTRAINT trust_signals_result_chk CHECK (
        result IN ('pass', 'fail', 'skip', 'error')
    )
);

CREATE INDEX IF NOT EXISTS idx_trust_signals_result 
    ON trust_signals(evidence_id, result);

CREATE INDEX IF NOT EXISTS idx_trust_signals_layer 
    ON trust_signals(layer, check_name, result);

COMMENT ON TABLE trust_signals IS 
    'Queryable trust signals for each evidence verification check';
COMMENT ON COLUMN trust_signals.layer IS 
    'Verification layer: identity (Layer 1), quality (Layer 2), attestation (Layer 3)';
COMMENT ON COLUMN trust_signals.check_name IS 
    'Specific check: publisher_auth, schema, provenance, executor, freshness, relevance';
```

**Example queries:**

```sql
-- Show me all evidence where freshness failed but everything else passed
SELECT evidence_id 
FROM evidence e
WHERE NOT EXISTS (
    SELECT 1 FROM trust_signals ts
    WHERE ts.evidence_id = e.evidence_id 
    AND ts.result = 'fail'
    AND ts.check_name != 'freshness'
)
AND EXISTS (
    SELECT 1 FROM trust_signals ts
    WHERE ts.evidence_id = e.evidence_id
    AND ts.check_name = 'freshness'
    AND ts.result = 'fail'
);

-- Evidence from unauthorized publishers
SELECT evidence_id, submitted_by, target_id
FROM evidence e
JOIN trust_signals ts ON ts.evidence_id = e.evidence_id
WHERE ts.check_name = 'publisher_auth'
AND ts.result = 'fail';

-- Trust signal distribution
SELECT check_name, result, COUNT(*)
FROM trust_signals
WHERE checked_at > NOW() - INTERVAL '7 days'
GROUP BY check_name, result
ORDER BY check_name, result;
```

#### target_trusted_publishers

**Purpose:** Target-scoped publisher authorization.

```sql
CREATE TABLE IF NOT EXISTS target_trusted_publishers (
    target_id         TEXT NOT NULL,
    issuer            TEXT NOT NULL,  -- OIDC provider URL
    sub_pattern       TEXT NOT NULL,  -- Glob pattern for sub claim
    environment       TEXT,           -- Optional GitHub Actions environment
    added_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by          TEXT,           -- Publisher who authorized this
    tessera_log_index BIGINT,         -- TargetRegistration log index
    
    PRIMARY KEY (target_id, issuer, sub_pattern)
);

CREATE INDEX IF NOT EXISTS idx_target_publishers_target 
    ON target_trusted_publishers(target_id);

COMMENT ON TABLE target_trusted_publishers IS 
    'Target-scoped publisher authorization: only listed OIDC identities can submit evidence for each target';
COMMENT ON COLUMN target_trusted_publishers.sub_pattern IS 
    'Glob pattern: repo:acme/scanner:* or service-account@acme.iam.gserviceaccount.com';
COMMENT ON COLUMN target_trusted_publishers.environment IS 
    'Optional GitHub Actions environment (requires manual approval gate)';
```

**Example data:**

```sql
INSERT INTO target_trusted_publishers (target_id, issuer, sub_pattern, environment, added_by)
VALUES 
  ('arn:aws:eks:us-east-1:123:cluster/prod', 
   'https://token.actions.githubusercontent.com', 
   'repo:acme/compliance-scanner:*',
   'production',
   'repo:acme/infra:ref:refs/heads/main'),
   
  ('arn:aws:eks:us-east-1:123:cluster/prod',
   'https://accounts.google.com',
   'scanner-service@acme-prod.iam.gserviceaccount.com',
   NULL,
   'repo:acme/infra:ref:refs/heads/main');
```

#### witness_certifications

**Purpose:** Cryptographically signed attestation bundles for external verification.

```sql
CREATE TABLE IF NOT EXISTS witness_certifications (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id           TEXT NOT NULL,
    tessera_log_index     BIGINT NOT NULL,
    certification_bundle  JSONB NOT NULL,
    signature             TEXT NOT NULL,   -- Base64-encoded ES256 signature
    public_key_fingerprint TEXT NOT NULL,  -- SHA256 fingerprint
    signed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT witness_certifications_evidence_unique UNIQUE (evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_witness_certifications_tessera 
    ON witness_certifications(tessera_log_index);
CREATE INDEX IF NOT EXISTS idx_witness_certifications_signed_at 
    ON witness_certifications(signed_at DESC);

COMMENT ON TABLE witness_certifications IS 
    'Layer 3 attestations: cryptographically signed certification bundles for external verification (auditors, GRC platforms)';
COMMENT ON COLUMN witness_certifications.certification_bundle IS 
    'JSON bundle: {tessera_log_index, evidence_id, publisher, trust_signals, verified_at}';
COMMENT ON COLUMN witness_certifications.signature IS 
    'ES256 signature over certification_bundle, base64-encoded';
```

### Modified Tables

#### evidence

```sql
-- Add publisher metadata (from Tessera entry)
ALTER TABLE evidence 
    ADD COLUMN IF NOT EXISTS publisher_metadata JSONB;

COMMENT ON COLUMN evidence.publisher_metadata IS 
    'Publisher identity from metadata.publisher in Tessera entry: {issuer, subject, verified_at}';

-- Existing columns stay:
-- publisher_issuer TEXT       (for backward compat + indexing)
-- submitted_by TEXT            (for backward compat + indexing)
-- publisher_type TEXT          (for backward compat)
-- certified BOOLEAN            (now derived from trust_signals aggregate)
```

**Certified flag semantics:**

```sql
-- evidence.certified = true IFF all trust signals are "pass"
UPDATE evidence SET certified = (
    NOT EXISTS (
        SELECT 1 FROM trust_signals ts
        WHERE ts.evidence_id = evidence.evidence_id
        AND ts.result IN ('fail', 'error')
    )
    AND EXISTS (
        SELECT 1 FROM trust_signals ts
        WHERE ts.evidence_id = evidence.evidence_id
    )
);
```

#### targets

```sql
-- Alternative 1: Inline JSONB column (simpler)
ALTER TABLE targets 
    ADD COLUMN IF NOT EXISTS trusted_publishers JSONB;

COMMENT ON COLUMN targets.trusted_publishers IS 
    'Array of trusted publisher patterns: [{issuer, sub_pattern, environment}]';

-- Alternative 2: Separate table (normalized, easier queries)
-- Use target_trusted_publishers table (defined above)
```

**We recommend Alternative 1 (JSONB column)** for simplicity, matching how TargetRegistration artifacts are structured.

---

## Gemara Artifacts

### TargetRegistration with Trusted Publishers

```yaml
metadata:
  type: TargetRegistration
  id: target-reg-prod-eks-001
  date: "2026-05-29T10:00:00Z"
  gemara-version: "1.0.0"

target:
  id: arn:aws:eks:us-east-1:123456789:cluster/prod-cluster
  name: Production EKS Cluster
  description: Primary production Kubernetes cluster for customer-facing services
  
  technologies:
    - kubernetes
    - aws-eks
  
  environment:
    - production
  
  geopolitical:
    - us-east-1
  
  sensitivity:
    - confidential
  
  # Trusted publishers: only these OIDC identities can submit evidence
  trusted-publishers:
    # GitHub Actions workflow (with environment restriction)
    - issuer: https://token.actions.githubusercontent.com
      repository: acme/compliance-scanner
      workflow: scan.yml
      environment: production  # Requires manual approval gate
      
    # Google Cloud service account
    - issuer: https://accounts.google.com
      sub: scanner-service@acme-prod.iam.gserviceaccount.com
      
    # GitLab CI pipeline
    - issuer: https://gitlab.com
      project-path: acme/security-scanner
      ref: main
      ref-type: branch
```

**Updating trusted publishers:**

Submit a new TargetRegistration artifact with updated `trusted-publishers` array. Newer `tessera_log_index` supersedes previous registration.

### EvaluationLog with Publisher Metadata

**Layer 1 augments artifact after JWT verification:**

```yaml
metadata:
  type: EvaluationLog
  id: eval-trivy-prod-001
  date: "2026-05-29T12:00:00Z"
  gemara-version: "1.0.0"
  
  # Added by Layer 1 after JWT signature verification
  publisher:
    issuer: https://token.actions.githubusercontent.com
    subject: repo:acme/compliance-scanner:ref:refs/heads/main
    verified-at: "2026-05-29T12:00:15Z"
  
  # Optional: full JWT claims for audit trail
  publisher-claims:
    aud: complytime-core
    iss: https://token.actions.githubusercontent.com
    sub: repo:acme/compliance-scanner:ref:refs/heads/main
    repository: acme/compliance-scanner
    repository-owner: acme
    workflow: .github/workflows/scan.yml
    ref: refs/heads/main
    sha: abc123def456789
    event-name: push
    run-id: "1234567890"
    run-attempt: "1"

target:
  id: arn:aws:eks:us-east-1:123456789:cluster/prod-cluster

engine:
  name: trivy
  version: 0.50.0
  
policy:
  id: iso-42001-policy
  version: "1.0"

results:
  - evidence-id: trivy-cve-2024-1234
    rule-id: CVE-2024-1234
    rule-name: Critical vulnerability in nginx
    eval-result: Failed
    compliance-status: Non-Compliant
    control-id: A.12.6.1
    requirement-id: req-001
    collected-at: "2026-05-29T11:55:00Z"
    # ... rest of evidence fields ...
```

---

## NIST 800-53 Mapping

### FedRAMP High Required Controls

| Control | Layer | Requirement | Implementation |
|---------|-------|-------------|----------------|
| **CM-14: Signed Components** | L1 | Prevent installation without digital signature verification | JWT signature verification via OIDC before accepting evidence |
| **SI-7(15): Code Authentication** | L1 | Cryptographic authentication prior to installation | coreos/go-oidc validates JWT signature against JWKS |
| **AC-3: Access Enforcement** | L2 | Enforce approved authorizations for logical access | PublisherAuthorizationValidator checks target-scoped authorization |
| **AC-6: Least Privilege** | L2 | Employ least privilege for specific duties | Target-scoped (not global) publisher authorization |
| **SR-3: Supply Chain Controls** | L2 | Protect against supply chain risks | Quality validators (schema/provenance/executor/freshness/relevance) |
| **SR-4: Provenance** | L1/L2 | Document, monitor, maintain valid provenance | `metadata.publisher` in Tessera + re-derivation in L2 |
| **SR-4(1): Provenance — Identity** | L2 | Unique identification of supply chain elements | Publisher (iss + sub) from JWT, re-derived from Tessera |
| **AU-9: Protection of Audit Information** | L3 | Protect audit info from unauthorized access/modification | Tessera append-only log with Merkle tree |
| **AU-9(3): Cryptographic Protection** | L3 | Cryptographic mechanisms to protect integrity | Witness ES256 signatures on certification bundles |
| **AU-10: Non-repudiation** | L1/L3 | Provide irrefutable evidence actions occurred | JWT (L1) + Tessera immutability + witness signature (L3) |
| **AU-11: Audit Record Retention** | L3 | Retain audit records per policy | Tessera + certifications table (indefinite retention) |
| **SI-7: Software Integrity** | L2 | Detect unauthorized changes | Freshness/relevance validators |
| **SI-7(6): Cryptographic Protection** | L3 | Detect unauthorized changes via checksums | Witness re-verifies publisher, signs aggregate |

### Control Justification Examples

**For auditors/assessors:**

**AC-6 (Least Privilege):**
> ComplyTime implements least privilege for evidence publishers through target-scoped authorization. Each target defines specific OIDC identities (GitHub Actions workflows, service accounts) authorized to submit evidence. Publishers can ONLY submit for targets they're explicitly trusted for, not globally. This prevents lateral movement: a compromised scanner for development cannot inject evidence for production targets.
> 
> Implementation: `target.trusted-publishers` array in TargetRegistration Gemara artifact, enforced by PublisherAuthorizationValidator in Layer 2. Verification logged in `trust_signals` table with reason.

**AU-10 (Non-repudiation):**
> ComplyTime provides multi-layer non-repudiation:
> 1. **Layer 1:** JWT signature from OIDC provider proves publisher identity at ingest time (who submitted)
> 2. **Tessera:** Append-only transparency log with Merkle tree prevents retroactive modification (what was submitted, when)
> 3. **Layer 3:** Witness ES256 signature on certification bundle proves "ComplyTime verified this evidence at time T" (independent attestation)
> 
> External parties can cryptographically verify the witness signature using our published public key. Publisher cannot deny submitting evidence (JWT signature), we cannot deny verifying it (witness signature).

**SR-4 (Provenance):**
> Every evidence artifact in Tessera includes `metadata.publisher` with cryptographically verified OIDC identity (issuer, subject, verified-at timestamp). Layer 2 re-derives publisher from Tessera entry (defense against NATS payload spoofing). Layer 3 witness independently re-verifies publisher identity. Full JWT claims preserved in `metadata.publisher-claims` for audit trail.
> 
> Provenance is immutable (Tessera append-only), queryable (`trust_signals.publisher_auth`), and verifiable by external parties (witness signature).

---

## Migration Path

### Phase 1: Add Trust Signals (Backward Compatible)

**Goal:** Replace binary `certified` flag with queryable trust signals, no breaking changes.

**Steps:**
1. Add `trust_signals` table migration
2. Layer 2 writes to BOTH `certifications` (old) AND `trust_signals` (new)
3. `evidence.certified` computed as aggregate of trust_signals
4. Existing queries work unchanged

**Migration:**

```sql
-- Migration 030: Add trust_signals table
CREATE TABLE IF NOT EXISTS trust_signals (
    evidence_id       TEXT NOT NULL,
    layer             TEXT NOT NULL,
    check_name        TEXT NOT NULL,
    result            TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (evidence_id, layer, check_name),
    CONSTRAINT trust_signals_layer_chk CHECK (layer IN ('identity', 'quality', 'attestation')),
    CONSTRAINT trust_signals_result_chk CHECK (result IN ('pass', 'fail', 'skip', 'error'))
);

CREATE INDEX idx_trust_signals_result ON trust_signals(evidence_id, result);
CREATE INDEX idx_trust_signals_layer ON trust_signals(layer, check_name, result);
```

**Backward compatibility:**
- `evidence.certified` stays as boolean (computed from trust_signals)
- `certifications` table stays (deprecated but not removed)
- UI works unchanged

---

### Phase 2: Add Target Authorization (Warnings Only)

**Goal:** Add publisher authorization infrastructure, log warnings (don't fail yet).

**Steps:**
1. Add `target_trusted_publishers` table migration
2. Update TargetRegistration parser to handle `trusted-publishers`
3. Layer 2 adds `publisher_auth` check (result logged, warnings only)
4. No evidence rejected yet (backward compatible)

**Migration:**

```sql
-- Migration 031: Add target_trusted_publishers
CREATE TABLE IF NOT EXISTS target_trusted_publishers (
    target_id         TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    sub_pattern       TEXT NOT NULL,
    environment       TEXT,
    added_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by          TEXT,
    tessera_log_index BIGINT,
    PRIMARY KEY (target_id, issuer, sub_pattern)
);

CREATE INDEX idx_target_publishers_target ON target_trusted_publishers(target_id);
```

**Deployment:**
1. Roll out code changes (parser, validator)
2. Existing targets have empty `trusted-publishers` → all publishers allowed (fallback)
3. Monitor logs for "unauthorized publisher" warnings
4. Teams add `trusted-publishers` to TargetRegistrations
5. When warnings trend to zero → ready for Phase 6 (enforcement)

---

### Phase 3: Embed Publisher in Tessera (Breaking Change)

**Goal:** Close NATS publisher identity gap.

**Steps:**
1. Layer 1 augments Gemara artifacts with `metadata.publisher`
2. Remove `PublisherIdentity` from NATS event payload (only `log_index` remains)
3. Layer 2 re-derives publisher from Tessera entry
4. **Breaking:** Old workers (that expect `PublisherIdentity` in NATS) stop working

**Migration:**

```sql
-- Migration 032: Add publisher_metadata to evidence
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS publisher_metadata JSONB;

COMMENT ON COLUMN evidence.publisher_metadata IS 
    'Publisher identity from metadata.publisher in Tessera entry';
```

**Deployment:**
1. **Stop old workers** (they won't parse `metadata.publisher` correctly)
2. Deploy new Layer 1 code (HTTP ingest handler)
3. Deploy new Layer 2 code (ingest worker)
4. Deploy new witness code
5. **No rollback:** Once Tessera has augmented artifacts, old workers can't process them

**Rollback plan:**
- If issues detected BEFORE deployment: don't deploy
- If issues detected AFTER deployment: requires emergency fix (can't roll back Tessera)

---

### Phase 4: Add Witness Certifications (Backward Compatible)

**Goal:** External verification via signed attestation bundles.

**Steps:**
1. Add `witness_certifications` table migration
2. Generate persistent ES256 keypair, store in Kubernetes secret
3. Witness signs certification bundles, writes to table
4. Add REST endpoint `GET /api/evidence/:id/certification`
5. Publish public key at `/.well-known/witness-public-key.pem`

**Migration:**

```sql
-- Migration 033: Add witness_certifications
CREATE TABLE IF NOT EXISTS witness_certifications (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id           TEXT NOT NULL,
    tessera_log_index     BIGINT NOT NULL,
    certification_bundle  JSONB NOT NULL,
    signature             TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    signed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT witness_certifications_evidence_unique UNIQUE (evidence_id)
);

CREATE INDEX idx_witness_certifications_tessera ON witness_certifications(tessera_log_index);
CREATE INDEX idx_witness_certifications_signed_at ON witness_certifications(signed_at DESC);
```

**Deployment:**
1. Generate ES256 keypair: `openssl ecparam -genkey -name prime256v1 -noout -out private-key.pem`
2. Extract public key: `openssl ec -in private-key.pem -pubout -out public-key.pem`
3. Create Kubernetes secret: `kubectl create secret generic witness-signing-key --from-file=private-key.pem --from-file=public-key.pem`
4. Deploy witness service (reads secret, signs bundles)
5. Deploy API changes (new endpoint)
6. Test: `curl /api/evidence/:id/certification | jq`

**Backward compatibility:**
- New feature, doesn't affect existing flows
- `evidence.certified` logic unchanged

---

### Phase 5: Implement Quality Validators (Backward Compatible)

**Goal:** Add FreshnessValidator, RelevanceValidator to Layer 2 pipeline.

**Steps:**
1. Implement FreshnessValidator (policy-aware staleness)
2. Implement RelevanceValidator (control/requirement existence)
3. Add to certifier pipeline after existing validators
4. Write `freshness` and `relevance` trust signals

**Code changes:**

```go
// cmd/gateway/main.go
func buildQualityPipeline() *quality.Pipeline {
    return quality.NewPipeline(
        &quality.SchemaValidator{},
        &quality.ProvenanceValidator{KnownRegistries: knownRegistries},
        &quality.ExecutorValidator{KnownEngines: knownEngines},
        &quality.FreshnessValidator{PolicyStore: policyStore},  // NEW
        &quality.RelevanceValidator{PolicyStore: policyStore},  // NEW
    )
}
```

**Deployment:**
- No migration needed (uses existing tables)
- Deploy code changes
- Monitor trust_signals for new check_name values (freshness, relevance)

**Backward compatibility:**
- New checks added, old checks unchanged
- `evidence.certified` logic still uses aggregate (all checks must pass)

---

### Phase 6: Enforce Publisher Authorization (Breaking Change)

**Goal:** Reject evidence from unauthorized publishers.

**Steps:**
1. Change `publisher_auth` from warning to FAIL
2. Evidence from non-authorized publishers rejected
3. **Breaking:** Requires all targets to have `trusted-publishers` configured

**Code changes:**

```go
// Before (Phase 2):
if !authorized {
    slog.Warn("unauthorized publisher for target",
        "target_id", row.TargetID,
        "publisher", row.SubmittedBy)
    // Continue processing (warning only)
}

// After (Phase 6):
if !authorized {
    return TrustSignal{
        Layer: "quality",
        Check: "publisher_auth",
        Result: "fail",
        Reason: "publisher not authorized for target",
    }
}
```

**Pre-deployment checklist:**
1. Query for targets without `trusted-publishers`: `SELECT target_id FROM targets WHERE trusted_publishers IS NULL OR jsonb_array_length(trusted_publishers) = 0`
2. Notify target owners to add `trusted-publishers` to TargetRegistrations
3. Monitor trust_signals: `SELECT COUNT(*) FROM trust_signals WHERE check_name = 'publisher_auth' AND result = 'fail'`
4. When fail count is acceptable → deploy enforcement

**Deployment:**
- Deploy code changes
- Evidence from unauthorized publishers now FAILS certification
- Monitor for unexpected failures
- If widespread failures → emergency rollback

**Rollback:**
- Revert code to Phase 2 (warnings only)
- Redeploy

---

## Implementation Issues

### Epic: Stratified Trust Layers Architecture

**Priority:** P1  
**Labels:** type/epic, area/architecture

**Description:**

Implement three-layer trust architecture (Identity, Quality, Attestation) with target-scoped publisher authorization and queryable trust signals. Replaces binary `certified` flag, closes NATS publisher identity gap (Issue #37), enables external verification via witness signatures.

**Business Value:**
- Satisfies NIST 800-53 Rev 5 controls for FedRAMP High
- Prevents unauthorized evidence submission (target-scoped authorization)
- Queryable trust signals for audit/investigation
- External verification for auditors/GRC platforms

**Related ADRs:**
- Evidence Quality Boundary (ADR 0033)
- Witness Service
- JWT Bearer Auth (ADR 0027)

**NIST 800-53 Controls:** CM-14, SI-7(15), AC-3, AC-6, AU-9, AU-9(3), AU-10, SR-3, SR-4, SR-4(1), SI-7, SI-7(6), AU-11

**Dependencies:** None

**Child Issues:** #1-17 below

---

### Layer 1: Identity Issues

**Issue #1: Embed publisher metadata in Tessera entries**

- **Priority:** P1
- **Labels:** area/ingest, area/auth
- **Description:** Layer 1 (HTTP ingest) augments Gemara artifacts with `metadata.publisher` after JWT verification. Publisher identity (iss, sub, verified-at) is cryptographically committed to Tessera entry.
- **Acceptance Criteria:**
  - [ ] Parse JWT, extract iss/sub/aud claims (coreos/go-oidc)
  - [ ] Augment artifact YAML with `metadata.publisher` section
  - [ ] Optional: include full claims in `metadata.publisher-claims`
  - [ ] Append augmented YAML to Tessera
  - [ ] Return log_index to caller
  - [ ] Unit tests for JWT claim extraction
  - [ ] E2E test: verify Tessera entry contains publisher metadata
- **NIST Controls:** CM-14, SI-7(15), SR-4

---

**Issue #2: Remove PublisherIdentity from NATS payload**

- **Priority:** P1
- **Labels:** area/ingest, type/breaking-change
- **Description:** NATS event only carries `log_index`. Closes NATS publisher identity gap (Issue #37). Worker re-derives publisher from Tessera entry.
- **Acceptance Criteria:**
  - [ ] Update `IngestRawEvent` struct: remove `PublisherIdentity` field
  - [ ] NATS event only has: job_id, log_index, yaml
  - [ ] Update all NATS publishers (HTTP handler, import handler)
  - [ ] Update all NATS subscribers (ingest worker)
  - [ ] Remove `PublisherIdentity` type from `internal/events`
  - [ ] Update tests
- **NIST Controls:** SR-4(1), AU-9
- **Closes:** #37
- **Depends On:** #1 (publisher metadata must be in Tessera first)

---

### Layer 2: Quality Issues

**Issue #3: Re-derive publisher identity from Tessera**

- **Priority:** P1
- **Labels:** area/ingest, area/store
- **Description:** Ingest worker reads Tessera entry at log_index, parses `metadata.publisher`, uses it for authorization checks. NATS payload cannot be trusted.
- **Acceptance Criteria:**
  - [ ] Worker reads Tessera entry (not NATS payload)
  - [ ] Parse `metadata.publisher` from YAML
  - [ ] Extract iss/sub/verified-at
  - [ ] Use for all downstream checks (replaces NATS PublisherIdentity)
  - [ ] Handle missing publisher metadata gracefully (skip publisher checks)
  - [ ] Unit tests for parser
  - [ ] E2E test: verify worker uses Tessera publisher, not NATS
- **NIST Controls:** SR-4(1), AU-9
- **Depends On:** #1 (publisher metadata must be in Tessera)

---

**Issue #4: Create trust_signals table**

- **Priority:** P1
- **Labels:** area/store, type/schema
- **Description:** Replace binary `certified` flag with queryable trust signals (identity, quality, attestation layers). Each check (publisher_auth, schema, freshness, etc.) writes one row.
- **Acceptance Criteria:**
  - [ ] Migration adds trust_signals table
  - [ ] Columns: evidence_id, layer, check_name, result, reason, checked_at
  - [ ] Constraints: layer IN (identity/quality/attestation), result IN (pass/fail/skip/error)
  - [ ] Indexes for querying by evidence_id, layer, result
  - [ ] Migration is backward compatible (existing tables unchanged)
  - [ ] Test migration rollback
- **NIST Controls:** AU-9, SI-7

---

**Issue #5: Add target_trusted_publishers table**

- **Priority:** P1
- **Labels:** area/store, type/schema
- **Description:** Target-scoped publisher authorization. Each target defines which OIDC identities (CI workflows, service accounts) are trusted to submit evidence.
- **Acceptance Criteria:**
  - [ ] Migration adds target_trusted_publishers table
  - [ ] Columns: target_id, issuer, sub_pattern, environment, added_at, added_by, tessera_log_index
  - [ ] Primary key: (target_id, issuer, sub_pattern)
  - [ ] Index on target_id for fast lookups
  - [ ] Comments document glob pattern format
  - [ ] Migration is backward compatible
- **NIST Controls:** AC-6, SR-3

---

**Issue #6: Implement PublisherAuthorizationValidator**

- **Priority:** P1
- **Labels:** area/certifier, area/auth
- **Description:** Layer 2 quality check that validates publisher identity (iss + sub) matches target's trusted publisher patterns. Glob matching for sub_pattern supports flexible configuration.
- **Acceptance Criteria:**
  - [ ] Implement PublisherAuthorizationValidator struct
  - [ ] Query latest TargetRegistration for target_id
  - [ ] Match publisher (iss + sub) against trusted_publishers array
  - [ ] Support glob patterns (*, repo:acme/scanner:*)
  - [ ] Write trust_signal: publisher_auth = pass/fail with reason
  - [ ] Initially log warnings (don't fail), Phase 6 makes it blocking
  - [ ] Unit tests for glob matching
  - [ ] E2E test: authorized publisher passes, unauthorized fails
- **NIST Controls:** AC-3, AC-6, SR-4(1)
- **Depends On:** #5 (target_trusted_publishers table)

---

**Issue #7: Implement FreshnessValidator**

- **Priority:** P2
- **Labels:** area/certifier, enhancement
- **Description:** Policy-aware freshness check. Query policy's assessment-plans[].frequency, compare evidence age against cycle. Fall back to 30-day default.
- **Acceptance Criteria:**
  - [ ] Implement FreshnessValidator struct
  - [ ] Query policy for requirement_id's assessment plan
  - [ ] Map frequency (daily/weekly/monthly/quarterly/annually) to days
  - [ ] Compare collected_at age against cycle days
  - [ ] on-demand frequency = never stale (always pass)
  - [ ] Fallback to 30-day default if no plan matches
  - [ ] Write trust_signal: freshness = pass/fail with reason
  - [ ] Reason includes: age, frequency, cycle days
  - [ ] Unit tests for all frequencies + fallback
  - [ ] E2E test: fresh evidence passes, stale evidence fails
- **NIST Controls:** SI-7
- **Closes:** #23

---

**Issue #8: Implement RelevanceValidator**

- **Priority:** P2
- **Labels:** area/certifier, enhancement
- **Description:** Validate evidence's control_id and requirement_id exist in declared policy. Orphaned evidence (invalid mapping) fails relevance.
- **Acceptance Criteria:**
  - [ ] Implement RelevanceValidator struct
  - [ ] Query policy for control_id
  - [ ] Query control for requirement_id
  - [ ] Write trust_signal: relevance = pass/fail
  - [ ] Reason includes which field was invalid (control vs requirement)
  - [ ] Unit tests for valid/invalid mappings
  - [ ] E2E test: valid mapping passes, orphaned evidence fails
- **NIST Controls:** SR-3
- **Closes:** #24

---

**Issue #9: Update TargetRegistration parser for trusted-publishers**

- **Priority:** P1
- **Labels:** area/ingest, area/store
- **Description:** Parse `target.trusted-publishers` array from TargetRegistration Gemara artifact, write to target_trusted_publishers table. Each target declares which OIDC identities are authorized.
- **Acceptance Criteria:**
  - [ ] Parse `target.trusted-publishers` array from YAML
  - [ ] Validate issuer (URL format)
  - [ ] Validate sub_pattern (or repository/workflow for GitHub)
  - [ ] Write to target_trusted_publishers table
  - [ ] Handle updates: new TargetRegistration supersedes old (newer tessera_log_index)
  - [ ] Clean up old entries for same target_id
  - [ ] Unit tests for parser
  - [ ] E2E test: submit TargetRegistration, verify table updated
- **NIST Controls:** AC-6, SR-4
- **Depends On:** #5 (target_trusted_publishers table)

---

### Layer 3: Attestation Issues

**Issue #10: Create witness_certifications table**

- **Priority:** P2
- **Labels:** area/witness, type/schema
- **Description:** Store cryptographically signed certification bundles. Bundle includes: Tessera log_index, evidence_id, publisher, all trust_signals, verified_at timestamp.
- **Acceptance Criteria:**
  - [ ] Migration adds witness_certifications table
  - [ ] Columns: evidence_id, tessera_log_index, certification_bundle (JSONB), signature, public_key_fingerprint, signed_at
  - [ ] Unique constraint on evidence_id
  - [ ] Indexes on tessera_log_index, signed_at
  - [ ] Comments document bundle schema
  - [ ] Migration is backward compatible
- **NIST Controls:** AU-9(3), AU-10

---

**Issue #11: Witness signs certification bundles**

- **Priority:** P2
- **Labels:** area/witness, enhancement
- **Description:** Witness aggregates trust_signals, signs certification bundle with persistent ES256 key, writes to witness_certifications table. Signature is for external verification (auditors, GRC platforms).
- **Acceptance Criteria:**
  - [ ] Query trust_signals for evidence_id
  - [ ] Build certification bundle JSON (schema: {tessera_log_index, evidence_id, publisher, trust_signals[], verified_at})
  - [ ] Sign bundle with ES256 private key
  - [ ] Base64-encode signature
  - [ ] Store bundle + signature + public key fingerprint
  - [ ] Only sign if ALL trust signals = pass
  - [ ] Unit tests for signing logic
  - [ ] E2E test: verify signature with public key
- **NIST Controls:** AU-9(3), AU-10, SI-7(6)
- **Depends On:** #10 (witness_certifications table), #12 (persistent key)

---

**Issue #12: Add persistent witness signing key**

- **Priority:** P2
- **Labels:** area/witness, type/chore
- **Description:** Replace ephemeral signer with persistent ES256 key (stored in Kubernetes secret). Signatures must be verifiable across restarts for external parties.
- **Acceptance Criteria:**
  - [ ] Generate ES256 keypair on first run (or load from secret)
  - [ ] Store private key in Kubernetes secret (`witness-signing-key`)
  - [ ] Load private key at startup
  - [ ] Compute SHA256 fingerprint of public key
  - [ ] Publish public key at `/.well-known/witness-public-key.pem`
  - [ ] Include fingerprint in all signatures (certifications table)
  - [ ] Document key rotation procedure
  - [ ] Test key rotation: old signatures remain valid
- **NIST Controls:** AU-9(3), AU-10

---

**Issue #13: REST endpoint for certification verification**

- **Priority:** P2
- **Labels:** area/api, enhancement
- **Description:** External parties (auditors, GRC platforms) can fetch certification bundle + signature for evidence. Response includes bundle, signature, public key fingerprint.
- **Acceptance Criteria:**
  - [ ] Add `GET /api/evidence/:id/certification` endpoint
  - [ ] Return JSON: {evidence_id, tessera_log_index, certification: {bundle, signature, public_key_fingerprint}}
  - [ ] 404 if evidence not certified yet
  - [ ] Document verification procedure in README
  - [ ] Add example verification script (bash + OpenSSL)
  - [ ] Unit tests for endpoint
  - [ ] E2E test: fetch certification, verify signature
- **NIST Controls:** AU-10, SI-7(6)
- **Depends On:** #11 (witness signs bundles)

---

### Infrastructure & Documentation Issues

**Issue #14: Update Gemara schema for publisher metadata**

- **Priority:** P1
- **Labels:** area/gemara, type/schema
- **Description:** Add `metadata.publisher` to Gemara schema definitions (EvaluationLog, EnforcementLog, AuditLog). Fields: issuer, subject, verified-at, optional publisher-claims.
- **Acceptance Criteria:**
  - [ ] Update Gemara CUE schema for EvaluationLog
  - [ ] Update Gemara CUE schema for EnforcementLog
  - [ ] Update Gemara CUE schema for AuditLog
  - [ ] Add `metadata.publisher` object: issuer (string, URL), subject (string), verified-at (time.Time)
  - [ ] Add optional `metadata.publisher-claims` object (arbitrary claims)
  - [ ] Update schema examples in docs/
  - [ ] Validate against gemara-mcp tool
- **Depends On:** None (can do in parallel with implementation)

---

**Issue #15: Update Gemara schema for TargetRegistration.trusted-publishers**

- **Priority:** P1
- **Labels:** area/gemara, type/schema
- **Description:** Add `target.trusted-publishers` array to TargetRegistration schema. Supports GitHub Actions, Google Cloud, GitLab CI patterns.
- **Acceptance Criteria:**
  - [ ] Update Gemara CUE schema for TargetRegistration
  - [ ] Add `target.trusted-publishers` array
  - [ ] Support GitHub Actions: issuer, repository, workflow, environment
  - [ ] Support Google Cloud: issuer, sub (service account email)
  - [ ] Support GitLab CI: issuer, project-path, ref, ref-type
  - [ ] Support generic: issuer, sub_pattern (glob)
  - [ ] Update schema examples
  - [ ] Validate against gemara-mcp tool
- **Depends On:** None

---

**Issue #16: ADR: Stratified Trust Layers Architecture**

- **Priority:** P1
- **Labels:** documentation, type/adr
- **Description:** Document the three-layer trust architecture, target-scoped publisher authorization, NIST 800-53 control mapping, migration path. This ADR explains WHY we're building this (business value, compliance requirements).
- **Acceptance Criteria:**
  - [ ] Write ADR to docs/decisions/stratified-trust-layers.md
  - [ ] Explain problem statement (what attacks/failures are we preventing)
  - [ ] Document three layers (Identity, Quality, Attestation) with responsibilities
  - [ ] Explain target-scoped authorization model
  - [ ] Map to NIST 800-53 Rev 5 controls
  - [ ] Include migration phases (1-6)
  - [ ] Document alternatives considered (why not global authorization, why not binary certified)
  - [ ] Link to related ADRs (Evidence Quality Boundary, Witness Service, JWT Bearer Auth)

---

**Issue #17: Migration guide for existing deployments**

- **Priority:** P2
- **Labels:** documentation
- **Description:** Step-by-step guide for upgrading from current architecture to stratified trust layers. Covers backward compatibility, breaking changes, rollback plan.
- **Acceptance Criteria:**
  - [ ] Write guide to docs/operations/stratified-trust-migration.md
  - [ ] Document each migration phase (1-6) with steps
  - [ ] Include SQL migrations for each phase
  - [ ] Backward compatibility notes per phase
  - [ ] Rollback procedures per phase
  - [ ] Pre-deployment checklists (esp. Phase 6)
  - [ ] Testing checklist
  - [ ] Monitoring/observability recommendations
  - [ ] Link to ADR #16

---

## Summary

**17 issues total:**
- **Layer 1 (Identity):** 2 issues (P1)
- **Layer 2 (Quality):** 7 issues (5 P1, 2 P2)
- **Layer 3 (Attestation):** 4 issues (P2)
- **Infrastructure/Docs:** 4 issues (3 P1, 1 P2)

**Priority breakdown:**
- **11 P1 issues** (core architecture, breaking changes)
- **6 P2 issues** (enhancements, documentation)

**NIST 800-53 controls satisfied:**
- CM-14, SI-7(15), AC-3, AC-6, AU-9, AU-9(3), AU-10, AU-11, SR-3, SR-4, SR-4(1), SI-7, SI-7(6)

**Migration timeline estimate:**
- Phase 1-2: 2 weeks (backward compatible)
- Phase 3: 1 week (breaking change, coordinated deployment)
- Phase 4-5: 2 weeks (backward compatible)
- Phase 6: 1 week (breaking change, requires pre-deployment prep)

**Total: ~6 weeks** for full implementation + testing + documentation.
