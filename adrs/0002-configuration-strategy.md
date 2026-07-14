# Configuration Strategy

**Status:** Accepted
**Date:** 2026-07-10

## Decision

All three services use koanf v2 for configuration with a unified precedence model:

**flags > env vars > config file > defaults**

- A YAML config file is the source of truth for each service.
- Any config value can be overridden by an env var named after its path (e.g., `COMPLYTIME_NATS_URL` overrides `nats.url` in the YAML).
- Flags override everything, for debugging and one-off runs.

Each service has its own config struct in `internal/<service>/config.go`. Shared fields (NATS URL, listen address, log level) use the same YAML key names across services for consistency.

Dependencies: `koanf/v2` core + `providers/file` + `providers/env` + `parsers/yaml`.

## Context

The previous project used env-var-only configuration via a flat `GatewayConfig` struct. This worked for simple cases but became awkward for list values (JWT issuers, CORS origins) and nested config. With three services, a consistent pattern is needed.

Three sources were considered: env vars, flags, and config files. All three are useful in different contexts:
- Config files are version-controllable, diffable, and natural for complex values.
- Env vars are the standard for container orchestration (Docker, Kubernetes).
- Flags are essential for debugging and one-off runs.

## Alternatives Considered

### Viper

The Go standard for configuration. Rejected because it uses a global singleton by default, pulls in many transitive dependencies, and is heavier than needed for this project.

### Roll our own (YAML unmarshal + env var overlay)

~50-100 lines, no external dependency. Rejected because maintaining config merging logic (especially flag binding and nested key override) is more work than importing a small library that does it well.

### Env vars only (12-factor)

What the old project did. Rejected because list and nested values are awkward in env vars, and the gateway has enough config surface that a YAML file is more maintainable.

### Config file as the only source (no env var override)

Clean mental model but fights Kubernetes/Docker conventions where env var injection is native. Secrets management is also harder without env var injection from K8s Secrets or Vault.

## Related

- [ADR 0001: Evidence Locker Architecture](./0001-evidence-locker-architecture.md)
- [koanf v2](https://github.com/knadh/koanf) — MIT license, used by OpenTelemetry Collector
