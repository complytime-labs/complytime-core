# Getting Started

## Prerequisites

- [Go 1.25+](https://go.dev/dl/)
- [Docker](https://docs.docker.com/get-docker/) or [Podman](https://podman.io/)

## Build

```bash
make build
```

Produces `bin/gateway` and `bin/locker`.

## Run Tests

```bash
# Unit tests
make test

# Integration tests (full lifecycle with embedded NATS)
go test ./internal/gateway/ -tags integration -v
```

## Run with Docker Compose

```bash
cd deploy/compose
docker compose up --build
```

This starts three services:
- **NATS** (JetStream enabled) on port 4222
- **Locker** on port 8081 (internal)
- **Gateway** on port 8080

The gateway requires JWT configuration. Set `OIDC_ISSUER` to your IdP's URL.

**Authorization** supports two models — Cedar policies accept either. For most deployments with a centrally managed IdP, set `OIDC_GROUP_CLAIM` to the dot-path of the group claim in the JWT (e.g., `realm_access.roles` for Keycloak) and assign users to recognized roles. This requires no IdP-side scope configuration. Alternatively, configure custom OAuth2 scopes (`complytime:admin`, `complytime:audit`) if your IdP supports it. See the [E2E testing guide](dev/e2e-testing.md#group-based-authorization) for details.

### Verify Services

```bash
# Gateway health
curl http://localhost:8080/healthz

# Locker health (requires shared secret from LOCKER_SECRET env var)
curl -H "Authorization: Bearer $LOCKER_SECRET" http://localhost:8081/healthz
```

## Project Structure

```
cmd/
  gateway/       # Evidence Gateway entry point
  locker/        # Evidence Locker entry point
api/
  gateway/       # Gateway OpenAPI spec + codegen config
  locker/        # Locker OpenAPI spec + codegen config
internal/
  gateway/       # Gateway handlers, worker, trust, events, receipts
  locker/        # Locker core, handlers, ledger, tileserver
  authz/         # Cedar authorization middleware
  nats/          # NATS connection, streams, subjects
adrs/            # Architecture Decision Records
deploy/compose/  # Docker Compose for local development
```

## Next Steps

- Read the [Architecture](architecture.md) doc for component details
- Review the [ADRs](../adrs/) for design decisions
- See the [Gateway OpenAPI spec](../api/gateway/openapi.yaml) for the full API contract
