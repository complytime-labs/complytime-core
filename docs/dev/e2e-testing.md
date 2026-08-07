# E2E Testing Paths by Role

End-to-end testing flows for each role in ComplyTime: **Admin**, **Publisher**, and **Auditor**.

## Setup

Start the full stack with Keycloak:

```bash
podman-compose -f deploy/compose/docker-compose.yaml --profile keycloak up -d
```

Without `--profile keycloak`, services start but Keycloak is absent — only testjwks-issued tokens work (publisher-class only; no scope-based admin or audit).

Stack ports:

| Service   | Port | Notes                          |
|-----------|------|--------------------------------|
| Keycloak  | 8080 | Only with `--profile keycloak` |
| Gateway   | 8090 | 8080 reserved for Keycloak     |
| Locker    | 8081 |                                |
| Graph     | 8082 |                                |
| testjwks  | 8888 |                                |
| NATS      | 4222 |                                |

---

## Authorization Model

Authorization uses Cedar policies with two principals:

- **Publisher** — workload identity (CI pipeline, scanner). Gate 1: issuer class (`publisher=true`, set at token validation for registered publisher issuers). Gate 2: subject-level trust registration in the trust store.
- **Human user** — Keycloak identity with OAuth2 scopes in the JWT `scope` claim.

### Scopes

| Scope              | Grants                                        |
|--------------------|-----------------------------------------------|
| `complytime:admin` | Subject registration, trust modification, evidence query |
| `complytime:audit` | Evidence query (read-only)                    |
| `complytime:read`  | Basic read access                             |

Keycloak users request scopes explicitly in the token grant. The Keycloak `complytime` client defines these as optional scopes — any authenticated user can request them in the dev stack. Production deployments should add Keycloak Authorization Services policies to restrict scope issuance by role.

### Group-Based Authorization

ComplyTime supports two authorization models: OAuth2 scopes and IdP group claims. Cedar policies accept either — operators choose based on what their IdP integration supports.

**Group-based** is the recommended path for most deployments with a centrally managed IdP. Groups and roles already exist in the directory (Keycloak, AD, LDAP); no IdP-side scope configuration is needed. Set `OIDC_GROUP_CLAIM` and assign users to the recognized roles.

**Scope-based** requires configuring custom OAuth2 scopes (`complytime:admin`, `complytime:audit`) in the IdP, which may not be possible when the IdP is shared or managed by another team.

**Configuration:**

Set `OIDC_GROUP_CLAIM` to the dot-path of the group claim in your IdP's JWT. Common paths by provider:

- **Dex**: `groups` — flat claim list in token root
- **Keycloak**: `realm_access.roles` — nested under `realm_access` object
- **Okta**: `groups` — flat claim list (may require API token to include)

**Environment Setup:**

```bash
export OIDC_ISSUER="https://dex.example.com"
export OIDC_GROUP_CLAIM="realm_access.roles"  # or "groups" for Dex/Okta
```

When `OIDC_GROUP_CLAIM` is set, the gateway extracts group membership from the JWT, normalizes to lowercase, filters to recognized groups, and passes them to Cedar policies.

| Group                   | Grants                                        |
|-------------------------|-----------------------------------------------|
| `complytime-admin`      | Subject registration, trust modification, evidence query |
| `complytime-auditor`    | Evidence query (read-only)                    |

**Group name requirements:** These exact names are hardcoded in Cedar policies (`internal/authz/policies/base.cedar`) and enforced by an application-level allowlist. Groups not in this list are silently dropped. Case is normalized to lowercase (e.g., `ComplyTime-Admin` becomes `complytime-admin`). If your IdP uses different role names, either:

1. Rename the roles in your IdP to match, or
2. Add custom Cedar policies in `CEDAR_POLICY_DIR` that recognize your role names.

Publisher access is **not** granted via groups. The `publisher` flag is set by the application based on the token's issuer URL (see `IssuerRegistry` in `internal/authn/registry.go`). Only tokens from configured publisher issuers (GitHub Actions, GitLab CI, GCP Workload Identity, Kubernetes service accounts, SPIFFE) can publish artifacts.

**Example: Token Claims with Keycloak Groups**

```json
{
  "sub": "alice@example.com",
  "email": "alice@example.com",
  "realm_access": {
    "roles": ["complytime-admin", "other-app-role"]
  }
}
```

Extract command:
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.realm_access.roles'
# ["complytime-admin", "other-app-role"]
```

**Example: Dex Groups in Dev Stack**

If running Dex in the Keycloak profile for testing, configure a static user with group claim:

```yaml
# In docker-compose.yaml dex config
connectors:
  - type: mockCallback
    id: mock
    name: Example
    config:
      username: user@example.com
      userID: "12345"
      groups:
        - complytime-admin
        - complytime-auditor
```

Then extract with:
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.groups'
# ["complytime-admin", "complytime-auditor"]
```

**Debugging Access Denials**

Authorization failures log to gateway stdout with structured fields including extracted scopes and groups:

```json
{"level":"warn","msg":"Cedar authorization denied","scopes":["openid"],"groups":["complytime-admin"],"reasons":["policy0"]}
```

Common issues:

- **Empty `groups` array:** `OIDC_GROUP_CLAIM` path is wrong or the claim isn't in the token. Decode the JWT and verify the claim path: `echo $TOKEN | cut -d'.' -f2 | base64 -d | jq`.
- **Groups present but access denied:** Check for typos. Cedar matches exact strings after lowercase normalization. Unknown group names (not in the allowlist) are silently dropped.
- **Scopes work but groups don't:** Verify `OIDC_GROUP_CLAIM` is set on the gateway service.
- **Startup log confirms config:** Look for `"group-based authorization enabled"` with `claim_path` in the gateway startup log.

---

## Role 1: Admin

**IdP**: Keycloak — requests `complytime:admin` scope  
**Endpoints**:
- `POST /admin/subjects` — Register new subject with initial trusted publishers
- `PUT /admin/subjects/{subjectId}/trust` — Replace trust policy
- `GET /api/subjects` — Query evidence (all subjects)

### Admin E2E Flow

1. **Get admin token** — request `complytime:admin` scope explicitly:

   ```bash
   ADMIN_TOKEN=$(curl -s -X POST \
     http://localhost:8080/realms/complytime/protocol/openid-connect/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=complytime" \
     -d "client_secret=complytime-secret" \
     -d "username=admin" \
     -d "password=admin-password" \
     -d "grant_type=password" \
     -d "scope=complytime:admin" | jq -r '.access_token')
   ```

   Verify the token carries the scope:
   ```bash
   echo $ADMIN_TOKEN | cut -d'.' -f2 | base64 -d | jq '.scope'
   # "complytime:admin openid"
   ```

2. **Register a subject**:

   ```bash
   curl -s -X POST http://localhost:8090/admin/subjects \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "subjectId": "my-repo",
       "trustedPublishers": [
         { "issuer": "http://testjwks:8888", "sub": "test-publisher" }
       ]
     }'
   ```

   Response: `201 Created`.

3. **Modify trust policy** (replace publisher list):

   ```bash
   curl -s -X PUT http://localhost:8090/admin/subjects/my-repo/trust \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "trustedPublishers": [
         { "issuer": "http://testjwks:8888", "sub": "test-publisher" },
         {
           "issuer": "https://token.actions.githubusercontent.com",
           "sub": "repo:my-org/my-repo:ref:refs/heads/main"
         }
       ]
     }'
   ```

4. **Query all evidence**:

   ```bash
   curl http://localhost:8082/api/subjects \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
   ```

---

## Role 2: Publisher

**IdP**: testjwks (local dev), or CI platform OIDC (GitHub Actions, GitLab, GCP)  
**Endpoints**: `POST /api/ingest` — Submit evidence artifact  
**Header required**: `X-Subject-ID` — identifies the target subject

Publishers authenticate via workload identity (not Keycloak). The registry recognises the issuer URL as a publisher-class issuer and sets `publisher=true`. Cedar then checks that the subject is registered as trusting this `(issuer, sub)` pair.

### Publisher E2E Flow (local dev via testjwks)

1. **Get publisher token from testjwks**:

   ```bash
   PUBLISHER_TOKEN=$(curl -s -X POST http://localhost:8888/mint \
     -H "Content-Type: application/json" \
     -d '{
       "sub": "test-publisher",
       "audience": ["complytime-gateway"]
     }' | jq -r '.token')
   ```

   Note: `audience` is an array. `sub` must match a registered trust entry for the target subject.

2. **Submit evidence** (in-toto statement):

   ```bash
   curl -s -X POST http://localhost:8090/api/ingest \
     -H "Authorization: Bearer $PUBLISHER_TOKEN" \
     -H "Content-Type: application/json" \
     -H "X-Subject-ID: my-repo" \
     -d '{
       "_type": "https://in-toto.io/Statement/v1",
       "subject": [{"name": "my-artifact", "digest": {"sha256": "abc123..."}}],
       "predicateType": "https://slsa.dev/provenance/v1",
       "predicate": {}
     }'
   ```

   Response: `202 Accepted` with job ID.

   ```json
   {"jobId": "4cfb8424-c325-4f90-867c-6b68ca630542"}
   ```

---

## Role 3: Auditor

**IdP**: Keycloak — requests `complytime:audit` scope  
**Endpoints**:
- `GET /api/subjects` — List all subjects
- `GET /api/subjects/{subjectId}/evidence` — Evidence for a subject

### Auditor E2E Flow

1. **Get auditor token** — request `complytime:audit` scope:

   ```bash
   AUDITOR_TOKEN=$(curl -s -X POST \
     http://localhost:8080/realms/complytime/protocol/openid-connect/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=complytime" \
     -d "client_secret=complytime-secret" \
     -d "username=auditor" \
     -d "password=auditor-password" \
     -d "grant_type=password" \
     -d "scope=complytime:audit" | jq -r '.access_token')
   ```

2. **List all subjects**:

   ```bash
   curl http://localhost:8082/api/subjects \
     -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .
   ```

3. **Get evidence for a subject**:

   ```bash
   curl "http://localhost:8082/api/subjects/my-repo/evidence" \
     -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .
   ```

   Evidence is indexed asynchronously — allow ~5 s after ingest before querying.

---

## Keycloak Dev Users

| Username  | Password           | Client Role          | Scope to request    |
|-----------|--------------------|----------------------|---------------------|
| admin     | admin-password     | complytime-admin     | `complytime:admin`  |
| publisher | publisher-password | complytime-publisher | (not Keycloak-based)|
| auditor   | auditor-password   | complytime-auditor   | `complytime:audit`  |

Client: `complytime` / `complytime-secret`

The dev stack does not enforce that the `complytime:admin` scope may only be requested by users with the `complytime-admin` role — any authenticated user can request it. Production deployments must add Keycloak Authorization Services scope policies to enforce this.

---

## Debugging

**Inspect token claims:**
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .
```

**Verify subject trust is registered:**
```bash
curl http://localhost:8081/ledgers/my-repo \
  -H "Authorization: Bearer $TOKEN"
```

**Check graph indexing** (graph logs when indexing succeeds):
```bash
podman logs compose_graph_1 | grep "sealed and processed"
```
