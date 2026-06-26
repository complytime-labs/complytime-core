# Getting Started

## Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [Docker](https://docs.docker.com/get-docker/) or [Podman](https://podman.io/)

## Quick Start

```bash
# Setup witness keys and start the stack
./scripts/setup-witness.sh
cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d

# Get a test JWT
TOKEN=$(curl -s http://localhost:9090/token?sub=repo:complytime-labs/complytime-core)

# Submit an EvaluationLog
curl -X POST http://localhost:8080/api/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-Email: dev@complytime.dev" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @examples/evaluation-log.yaml
```

## Running Tests

```bash
make test                # Unit tests
make test-integration    # Integration (Ginkgo, in-process Tessera)
```

## Smoke Test

```bash
./scripts/smoke-test.sh  # Full stack verification (requires compose up)
```

## Troubleshooting

- `make lint` — run linters locally
- Check `NATS_URL` is set and reachable
- Ingest service logs to stdout with `slog` — look for `async ingest` messages

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `NATS_URL` | (required) | NATS server URL |
| `TESSERA_PATH` | `/data/tessera` | POSIX storage path for the transparency log |
| `TESSERA_SIGNER_KEY_PATH` | (empty) | Persist Tessera signer key. Without this, the log identity changes on restart. |
| `JWT_ISSUERS` | (empty) | Comma-separated OIDC issuer URLs for publisher JWT verification |
| `JWT_AUDIENCE` | `complytime` | Expected JWT audience claim |
| `INGEST_RATE_LIMIT` | `10` | Requests/second per IP on `/api/ingest` |
| `INGEST_RATE_BURST` | `20` | Burst allowance for rate limiting |
