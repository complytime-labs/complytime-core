# Contributing to ComplyTime Core

## Dev Environment

See [Getting Started](docs/getting-started.md) for prerequisites, setup, and configuration.

**Local stack:**

```bash
./scripts/setup-witness.sh
cd deploy/compose && docker compose -f docker-compose.yaml -f docker-compose.testjwks.yml up --build -d
```

## Issue-Driven Development

Every PR must reference a GitHub issue. No one-off PRs. Issues are the entry
point for all work — they provide context, enable discussion before
implementation, and keep the backlog visible.

**Workflow:**

```text
Issue → Branch → PR (references issue) → Review → Merge
```

**Where does my contribution go?**

| If you have... | Then... |
| :-- | :-- |
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
go build ./cmd/ingest/
golangci-lint run -build-tags dev ./...
```

**Integration tests** (run locally before touching e2e code):

```bash
make test-integration
# or: go test -tags integration ./internal/e2e/ -run "Transparency"
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

## Testing

- Write tests for all code changes
- Go: table-driven tests, descriptive names, edge cases
- Run `make test` locally before submitting a PR
- Integration tests: `make test-integration`

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
