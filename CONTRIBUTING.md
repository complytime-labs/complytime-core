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

## Issue-Driven Development

Every PR must reference a GitHub issue. No one-off PRs. Issues are the entry
point for all work — they provide context, enable discussion before
implementation, and keep the backlog visible.

**Workflow:**

```
Issue → Branch → PR (references issue) → Review → Merge
```

**Where does my contribution go?**

| If you have... | Then... |
|:--|:--|
| A bug | File a [Bug Report](https://github.com/complytime-labs/complytime-core/issues/new?template=bug_report.yml) |
| A feature idea | File a [Feature Request](https://github.com/complytime-labs/complytime-core/issues/new?template=feature_request.yml) |
| An architectural question | File a [Design Discussion](https://github.com/complytime-labs/complytime-core/issues/new?template=design_discussion.yml) |
| Related work to group | File an [Epic](https://github.com/complytime-labs/complytime-core/issues/new?template=epic.yml) |

When in doubt, start with an issue.

**Design discussions** explore architectural questions before implementation. When
a design discussion converges on a decision, propose an
[ADR](docs/decisions/) via a PR. ADRs are frozen once accepted — if a decision
needs to change, write a new ADR that supersedes the old one. See the
[ADR template](docs/decisions/0000-template.md).

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

All work starts with a [GitHub Issue](https://github.com/complytime-labs/complytime-core/issues).
See [Issue-Driven Development](#issue-driven-development) for templates and
the contribution routing table.

**Labels:** We use `type/` (bug, feature, epic, design, chore), `P0-P2`
(priority), and `area/` (api, auth, certifier, ingest, store, witness) labels.
Maintainers apply these during triage. Good labels for contributors:
`good first issue`, `help wanted`.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
