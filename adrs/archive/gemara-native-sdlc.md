# Gemara-Native Security Development Lifecycle

**Date**: 2026-04-25
**Status**: Accepted

## Decision

Use Gemara artifacts to manage ComplyTime Studio's own security posture during development. A Cursor-based security analyst agent performs STRIDE threat modeling per feature and produces Layer 2 artifacts (CapabilityCatalog, ThreatCatalog, ControlCatalog). Deterministic scanners run in CI; an agentic scanner bridge interprets their output against the ControlCatalog and produces EvaluationLogs.

## Context

ComplyTime Studio builds tooling for compliance-as-code but does not apply it to its own development. Security analysis is ad hoc — no structured threat models, no machine-readable controls, no traceable link from threat to scanner finding.

The infrastructure to close this gap already exists in the repo:

| Piece | Status |
|:--|:--|
| STRIDE threat modeling skill | `~/.cursor/skills/stride-threat-model/SKILL.md` |
| Gemara MCP (validate, migrate) | Available locally via gemara-mcp |
| OpenSpec change lifecycle | Propose → implement → archive |
| CI pipeline | Go, lint, helm, workbench — no security scanning |

The missing link: structured artifacts that connect threat models to scanner output.

## Approach

### Actors

All actors operate in the developer's local environment (Cursor) or CI. None are ComplyTime Studio product features.

| Actor | Role | Environment |
|:--|:--|:--|
| Developer | Writes features via OpenSpec changes | Cursor |
| Security analyst agent | STRIDE analysis → Layer 2 artifacts | Cursor (skill + gemara-mcp) |
| Scanner bridge agent | Maps scanner output → EvaluationLog | Cursor (skill + gemara-mcp) |
| CI scanners | Deterministic analysis (Semgrep, etc.) | GitHub Actions |

### Dependency Chain

```
CapabilityCatalog → ThreatCatalog → ControlCatalog → Scanner rules → EvaluationLog
```

Scanner tooling (step 4) is derived from the ControlCatalog, not the other way around. Generic rulesets run as a baseline; custom rules map to specific controls.

### Workflow

1. Developer starts an OpenSpec change
2. Security analyst agent runs STRIDE on the design/implementation
3. Agent produces CapabilityCatalog, ThreatCatalog, ControlCatalog (validated via gemara-mcp)
4. Artifacts stored in the change directory or a central `security/` directory
5. Developer implements with threat model visible
6. CI runs deterministic scanners, outputs SARIF/JSON
7. Scanner bridge agent maps findings to ControlCatalog entries, produces EvaluationLog
8. Archive includes security artifacts as evidence

### Trigger

Per feature — aligned with the OpenSpec change lifecycle. Not per-PR (too noisy) or per-release (too late to inform implementation).

## What This Requires

| Deliverable | Type |
|:--|:--|
| Upgrade STRIDE skill to emit validated Gemara YAML | Skill enhancement |
| Security analyst Cursor skill or agent | New skill |
| Scanner bridge skill (SARIF → EvaluationLog) | New skill |
| Initial CapabilityCatalog for ComplyTime Studio | Gemara artifact |
| CI scanner integration (Semgrep) | GitHub Actions workflow |
| Artifact storage convention | Repo structure decision |

## What This Does Not Do

- Does not add features to ComplyTime Studio the product
- Does not deploy agents to a cluster
- Does not replace deterministic scanning with agentic scanning — the agent interprets, the scanner detects
- Does not require changes to the Gemara schema — all artifact types already exist

## Consequences

- Security analysis becomes a structured, traceable part of the development workflow
- Threat models persist as machine-readable artifacts, not ephemeral documents
- Scanner findings are mapped to controls, producing auditable EvaluationLogs
- The project dogfoods its own artifact format
- Adds process overhead per feature — mitigated by agent automation
- Requires initial investment to produce the baseline CapabilityCatalog and ThreatCatalog for the existing codebase
