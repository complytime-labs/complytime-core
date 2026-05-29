# Contributing to ComplyTime Studio

## Dev Environment

See [README.md](README.md) for prerequisites (Go, Node, Docker/Podman, kind, kubectl, Helm).

**Two modes:**

| Mode | Command | What you get |
|:--|:--|:--|
| Docker Compose | `cd ../studio-deploy && make up` | Full stack: gateway, workbench, UI, PostgreSQL, NATS, MCP servers |
| Kubernetes | `cd ../studio-deploy && make helm-install` | Kind cluster with all components |

Seed demo data after deploy:

```bash
make seed
```

When running in Kubernetes, `make seed` auto-extracts the API token from the cluster secret. For Docker Compose, the token is `studio-dev-token`.

## Code Contributions

**Branching:** Create feature branches from `main`. Keep PRs atomic — reviewable in one sitting.

**PR title format:** `<type>: <description>` per [Conventional Commits](https://www.conventionalcommits.org/).

**Commits:**

```bash
git commit -S -s -m "feat: add posture endpoint"
```

- `-S` GPG sign, `-s` Signed-off-by (both required)
- AI-assisted work adds an `Assisted-by: Cursor (<model>)` trailer

**CI gates** (must pass before merge):

```bash
go vet -tags dev ./...
go test -tags dev -race ./...
go build ./cmd/gateway/
golangci-lint run ./...
```

**Review:** 2 maintainer approvals required. Exceptions for transient CI failures require maintainer consensus.

## Go Standards

Conventions are defined in [AGENTS.md](AGENTS.md). Key points:

- File names: lowercase with underscores (`my_file.go`)
- Package names: short, lowercase, no underscores
- Always check and return errors
- Format with `goimports` and `go fmt`
- SPDX header: `// SPDX-License-Identifier: Apache-2.0`
- Line length: 99 characters max
- Linter config: [`.golangci.yml`](.golangci.yml)

## Frontend Standards

The Preact SPA lives in [studio-ui](https://github.com/complytime/studio-ui). Frontend contributions go to that repo.

## Agent and Skill Contributions

[AGENTS.md](AGENTS.md) describes the JTBD framework for agent design. Agents run inside the Studio Workbench container. The platform is **framework-agnostic** — any framework (LangGraph, CrewAI, custom) works as long as the agent speaks A2A.

**Modifying the assistant:**

Agent source (agent.yaml, prompt.md, skills, Python code) lives in the [complytime-studio](https://github.com/complytime-labs/complytime-studio) repo.

| Artifact | Location |
|:--|:--|
| Agent spec | `complytime-studio` repo: `agents/assistant/agent.yaml` |
| Prompt | `complytime-studio` repo: `agents/assistant/prompt.md` |
| Skills | `complytime-studio` repo: `skills/*/SKILL.md` |
| Helm chart | `studio-deploy` repo: `charts/complytime/` |
| Helm prompt values | `studio-deploy` repo: `charts/complytime/values.yaml` → `agentPrompts.assistant` |

After changing prompts, update `agentPrompts.assistant` in `studio-deploy/charts/complytime/values.yaml`.

**Adding a new agent:** See [AGENTS.md](AGENTS.md) for the full workflow and checklist.

## OpenSpec Changes

Design changes follow a structured workflow:

```
proposal.md -> design.md -> specs/ -> tasks.md -> implementation
```

All artifacts live in `openspec/changes/<change-name>/`. Templates are in `openspec/schemas/unbound-force/templates/`.

## Testing

- Write tests for all code changes
- Go: table-driven tests, descriptive names, edge cases
- Run `make test` locally before submitting a PR
- Integration tests requiring PostgreSQL use `POSTGRES_TEST_URL`

## Issues

Use [GitHub Issues](https://github.com/complytime-labs/complytime-core/issues) with the appropriate template:

- **Bug Report** — something isn't working
- **Feature Request** — propose a new feature or enhancement  
- **Epic** — group related work under a theme

**Labels:** We use `type/`, `P0-P2` (priority), and `area/` labels. Maintainers will apply these during triage. Good labels for contributors: `good first issue`, `help wanted`.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
