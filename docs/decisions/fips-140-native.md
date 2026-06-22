<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native FIPS 140-3 Build Support

**Status:** Accepted
**Date:** 2026-05-27

## Context

ComplyTime processes compliance evidence for regulated environments. Deployment targets may require FIPS 140-3 validated cryptography. Go 1.24+ ships native FIPS 140-3 support via the Go Cryptographic Module — no BoringCrypto fork, no third-party libraries needed.

## Decision

Use Go's native `GOFIPS140` build flag and `GODEBUG=fips140` runtime flag. FIPS builds are opt-in. Default builds are unchanged.

**Build-time activation:**
```bash
GOFIPS140=latest go build -o bin/complytime-ingest ./cmd/ingest/
```

**Runtime activation:**
```bash
GODEBUG=fips140=on ./bin/complytime-ingest
```

**Module version:** `GOFIPS140=latest` selects the best validated module available for the Go version (v1.0.0 on Go 1.24–1.25, CAVP Certificate A8028).

## What This Does NOT Cover

- **HTTP TLS configuration** — Deferred to service mesh (Istio/Envoy). The gateway binds to localhost behind OAuth2 Proxy.
- **NATS TLS hardening** — Separate roadmap item. When implemented, FIPS cipher constraints apply automatically.
- **PostgreSQL TLS hardening** — Separate roadmap item. Same automatic constraint inheritance.
- **REQUIRE_FIPS startup check** — Can add later if operators need a hard fail when FIPS is expected but not active.
- **CI pipeline changes** — Can add FIPS build verification later.

## Consequences

- Default builds unchanged — no impact on development workflow
- Operators activate FIPS via build flag (`GOFIPS140=latest`) or runtime env var (`GODEBUG=fips140=on`)
- Future NATS/PostgreSQL TLS work inherits FIPS cipher constraints automatically when the binary is built with FIPS
- No dependency on CrossCodex's FIPS approach (they use BoringCrypto via Red Hat UBI base images — different mechanism, same goal)
- Dockerfile supports `--build-arg GOFIPS140=latest` for container builds

## Related

- [Go FIPS 140-3 documentation](https://go.dev/doc/security/fips140)
- [CAVP Certificate A8028](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?id=A8028)
