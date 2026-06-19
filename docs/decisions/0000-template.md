# Title

**Status:** Proposed
**Date:** YYYY-MM-DD

## Decision

What are we doing and why? Lead with the decision, not the backstory.

## Context

What problem or tension motivated this decision?

## Architecture

_Optional._ Technical details, diagrams, schemas, query patterns.

## Security Properties

_Required if this decision claims any security guarantee (tamper-evidence,
non-repudiation, access control, confidentiality, etc.). Omit this section
only if the decision has no security implications._

If you claim a property, you must reference how it is verified:

| Property | Threat (STRIDE) | Control ID | Test |
|:--|:--|:--|:--|
| _e.g., "Checkpoints are cosigned"_ | _T-TAMP-01_ | _CTRL-AE-01_ | _witness_cosign_test.go: CTRL-AE-01.1_ |

- **Threat**: reference the STRIDE threat catalog entry, or describe the threat inline
- **Control ID**: reference the Gemara Layer 2 control, or describe the control inline
- **Test**: a Ginkgo spec, integration test, or conformance test that verifies the property from an external party's perspective

_If a property cannot be tested yet, mark it as "Not yet verified" with an
issue reference for the planned test. An unverified claim must not be stated
as an accepted guarantee._

## Alternatives Considered

_Optional. Include only when rejected alternatives add useful context._

### Alternative A

Why rejected.

## Related

- [ADR NNNN](./...) -- if this supersedes or relates to another ADR
- [Issue #NN](https://github.com/complytime-labs/complytime-core/issues/NN)
