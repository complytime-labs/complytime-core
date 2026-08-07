# Authorization Data Flow

How a request moves from HTTP entry through authentication, context
enrichment, and Cedar policy evaluation.

## Authorization Architecture (P\*P Pattern)

ComplyTime follows the XACML-derived P\*P authorization architecture,
with Cedar as the policy engine:

| Component | Role | Implementation |
|-----------|------|----------------|
| **PEP** (Policy Enforcement Point) | Intercepts requests, enforces allow/deny | `authz.Middleware` — returns 403 on deny |
| **PDP** (Policy Decision Point) | Evaluates policies, returns decisions | Cedar engine (`cedar.Authorize`) |
| **PIP** (Policy Information Point) | Provides attributes for decisions | Multiple sources (see below) |
| **PAP** (Policy Administration Point) | Manages policies | Embedded `base.cedar` + operator overlay via `CEDAR_POLICY_DIR` |

### Policy Information Points

The PDP receives all attributes via the Cedar `EntityMap` — there is no
runtime attribute fetch during evaluation. The PEP assembles entities
from multiple PIPs before calling `Authorize`:

| PIP | Attributes | Source |
|-----|------------|--------|
| **OIDC token** (Keycloak/Dex) | `groups`, `scopes`, `issuer`, `sub` | JWT claims, validated via JWKS |
| **Issuer registry** | `publisher` (bool) | Issuer class dispatch — true for CI/CD issuers, false for human IdP |
| **Trust store** | `publisher_trusted` (bool) | NATS KV per-subject trust registration |
| **HTTP request** | action | Route mapping (`ActionForRoute`) |

This follows the standard XACML P*P separation: the PDP never fetches
attributes at evaluation time, and each PIP is independently replaceable
(swap Keycloak for another OIDC provider, swap NATS KV for another trust
store) without changing policies.

## Overview

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#2f6dab',
  'primaryTextColor': '#1e1e1e',
  'primaryBorderColor': '#7c8ba1',
  'lineColor': '#7c8ba1',
  'edgeLabelBackground': '#eef2f8',
  'tertiaryColor': 'transparent',
  'tertiaryTextColor': '#7c8ba1',
  'tertiaryBorderColor': '#7c8ba1',
  'clusterBkg': 'transparent',
  'clusterBorder': '#7c8ba1',
  'titleColor': '#7c8ba1',
  'noteBkgColor': '#eef2f8',
  'noteTextColor': '#1e1e1e',
  'fontFamily': 'system-ui, sans-serif'
}, 'themeCSS': '.node .nodeLabel{color:#ffffff!important;fill:#ffffff!important;}'}}%%
flowchart TD
  REQ["HTTP Request + Bearer JWT"]
  AUTH["AuthMiddleware"]
  REG["IssuerRegistry.Authenticate"]
  OIDC["OIDCIssuer"]
  PUB["PublisherIssuer"]
  PRIN["Principal{Issuer, Sub, Publisher, Scopes, Groups}"]
  CTX["Context Enrichment"]
  SUBJ["SubjectIDExtractor"]
  CEDAR["Cedar Middleware"]
  ACT["ActionForRoute"]
  TRUST["TrustStore.IsPublisherTrusted"]
  ENT["Build Cedar Entities"]
  EVAL["cedar.Authorize"]
  HANDLER["Route Handler"]
  DENY["403 Forbidden"]

  REQ -->|"Authorization header"| AUTH
  AUTH -->|"peek iss claim"| REG
  REG -->|"human IdP"| OIDC
  REG -->|"CI/CD issuer"| PUB
  OIDC -->|"scopes + groups from token"| PRIN
  PUB -->|"Publisher=true"| PRIN
  PRIN --> CTX
  CTX -->|"set publisher, scopes, groups, flag"| CEDAR
  SUBJ -->|"X-Subject-ID header"| CEDAR
  CEDAR --> ACT
  ACT -->|"HTTP route to Cedar action"| ENT
  CEDAR -->|"non-admin actions"| TRUST
  TRUST -->|"publisher_trusted bool"| ENT
  ENT -->|"Principal + Resource + Request"| EVAL
  EVAL -->|"permit"| HANDLER
  EVAL -->|"deny"| DENY

  classDef sysA fill:#2f6dab,color:#ffffff,stroke:#7c8ba1
  classDef sysB fill:#1d7848,color:#ffffff,stroke:#7c8ba1
  classDef sysC fill:#7457b8,color:#ffffff,stroke:#7c8ba1
  classDef sysD fill:#2d747e,color:#ffffff,stroke:#7c8ba1
  classDef sysF fill:#5c6a82,color:#ffffff,stroke:#7c8ba1
  class REQ,AUTH sysF
  class REG,OIDC,PUB,PRIN sysA
  class CTX,SUBJ sysB
  class CEDAR,ACT,TRUST,ENT,EVAL sysC
  class HANDLER sysD
  class DENY sysF
```

## Color key

| Color | Meaning |
|-------|---------|
| Slate (entry/exit) | HTTP boundary — request in, response out |
| Sapphire (authn) | Authentication — JWT validation, issuer dispatch, Principal construction |
| Emerald (context) | Context enrichment — storing identity data for downstream use |
| Amethyst (authz) | Authorization — Cedar action mapping, trust lookup, policy evaluation |
| Teal (handler) | Authorized handler execution |

## Authentication paths

Two issuer classes, routed by the `iss` claim in the JWT:

**Human IdP (OIDCIssuer)** — a Dex or Keycloak instance configured via
`OIDC_ISSUER`. Tokens carry OAuth2 scopes and/or IdP group claims.
`ExtractScopes` filters scopes to the `complytime:` namespace; `ExtractGroups`
normalizes to lowercase and filters to the `knownGroups` allowlist
(`complytime-admin`, `complytime-auditor`). Cedar policies accept either.
`Publisher` is false.

**CI/CD Publisher (PublisherIssuer)** — GitHub Actions, GitLab CI, GCP
Workload Identity, Kubernetes service accounts (EKS/GKE/AKS), SPIFFE, or
runtime-registered static JWK scanners.
`Publisher` is true; scopes are nil (publishers don't carry OAuth2 scopes).

## Cedar policy evaluation

The middleware builds three inputs for `cedar.Authorize`:

| Input | Source |
|-------|--------|
| **Principal** | `Publisher::"issuer::sub"` from JWT claims |
| **Action** | Mapped from HTTP method + route pattern |
| **Resource** | `Subject::subjectId` from `X-Subject-ID` header or `*` placeholder |

Entity attributes on Principal: `publisher` (bool), `scopes` (Set of
String), `groups` (Set of String), `issuer`, `sub`. On Resource:
`publisher_trusted` (bool from TrustStore).

## Policy decisions

| Action | Gate |
|--------|------|
| `publish:artifact` | `publisher == true` AND `publisher_trusted == true` |
| `admin:request-registration` | scopes contains `complytime:admin` OR groups contains `complytime-admin` |
| `admin:request-trust-modification` | scopes contains `complytime:admin` OR groups contains `complytime-admin` |
| `query:evidence` | scopes contains `complytime:audit`/`complytime:admin` OR groups contains `complytime-auditor`/`complytime-admin` |
| `read:evidence` | scopes contains `complytime:audit`/`complytime:admin` OR groups contains `complytime-auditor`/`complytime-admin` |

A `forbid` safety floor blocks `publish:artifact` if `publisher_trusted`
is false, regardless of other permits. Publisher access is never granted
via groups — it requires a CI/CD issuer class token.

## Sequence: publish artifact (CI/CD)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#2f6dab',
  'primaryTextColor': '#1e1e1e',
  'primaryBorderColor': '#7c8ba1',
  'lineColor': '#7c8ba1',
  'edgeLabelBackground': '#eef2f8',
  'tertiaryColor': 'transparent',
  'tertiaryTextColor': '#7c8ba1',
  'tertiaryBorderColor': '#7c8ba1',
  'clusterBkg': 'transparent',
  'clusterBorder': '#7c8ba1',
  'titleColor': '#7c8ba1',
  'noteBkgColor': '#eef2f8',
  'noteTextColor': '#1e1e1e',
  'fontFamily': 'system-ui, sans-serif'
}, 'themeCSS': '.node .nodeLabel{color:#ffffff!important;fill:#ffffff!important;}'}}%%
sequenceDiagram
  participant CI as GitHub Actions
  participant GW as Gateway
  participant IR as IssuerRegistry
  participant GH as GitHubActionsIssuer
  participant AM as AuthMiddleware
  participant SE as SubjectIDExtractor
  participant CM as Cedar Middleware
  participant TS as TrustStore
  participant CE as Cedar Engine
  participant H as IngestHandler

  CI->>GW: POST /api/ingest + Bearer JWT + X-Subject-ID
  GW->>AM: invoke middleware chain
  AM->>IR: Authenticate(token)
  IR->>IR: peek iss claim
  IR->>GH: Authenticate(token)
  GH->>GH: validate JWT via JWKS
  GH-->>IR: Principal{Publisher=true, Scopes=nil}
  IR-->>AM: Principal
  AM->>AM: set publisher context + flag
  AM->>SE: next handler
  SE->>SE: extract X-Subject-ID header
  SE->>CM: next handler
  CM->>CM: ActionForRoute = publish:artifact
  CM->>TS: IsPublisherTrusted(issuer, sub, subjectId)
  TS-->>CM: trusted=true
  CM->>CE: Authorize(principal, action, resource)
  CE-->>CM: permit
  CM->>H: next handler
  H-->>GW: 200 OK + receipt
```

## Sequence: admin registers subject (human)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#2f6dab',
  'primaryTextColor': '#1e1e1e',
  'primaryBorderColor': '#7c8ba1',
  'lineColor': '#7c8ba1',
  'edgeLabelBackground': '#eef2f8',
  'tertiaryColor': 'transparent',
  'tertiaryTextColor': '#7c8ba1',
  'tertiaryBorderColor': '#7c8ba1',
  'clusterBkg': 'transparent',
  'clusterBorder': '#7c8ba1',
  'titleColor': '#7c8ba1',
  'noteBkgColor': '#eef2f8',
  'noteTextColor': '#1e1e1e',
  'fontFamily': 'system-ui, sans-serif'
}, 'themeCSS': '.node .nodeLabel{color:#ffffff!important;fill:#ffffff!important;}'}}%%
sequenceDiagram
  participant U as Admin User
  participant GW as Gateway
  participant IR as IssuerRegistry
  participant OI as OIDCIssuer
  participant AM as AuthMiddleware
  participant CM as Cedar Middleware
  participant CE as Cedar Engine
  participant H as RegisterSubject

  U->>GW: POST /admin/subjects + Bearer JWT
  GW->>AM: invoke middleware chain
  AM->>IR: Authenticate(token)
  IR->>IR: peek iss claim
  IR->>OI: Authenticate(token)
  OI->>OI: validate JWT via OIDC discovery
  OI->>OI: ExtractScopes + ExtractGroups
  OI-->>IR: Principal{Publisher=false, Scopes=[], Groups=[complytime-admin]}
  IR-->>AM: Principal
  AM->>AM: set scopes + groups context
  AM->>CM: next handler
  CM->>CM: ActionForRoute = admin:request-registration
  Note over CM: no trust lookup for admin actions
  CM->>CE: Authorize(principal, action, resource)
  CE->>CE: groups.contains("complytime-admin")
  CE-->>CM: permit
  CM->>H: next handler
  H->>IR: ValidateTrustEntry(issuer, entry)
  H-->>GW: 201 Created
```
