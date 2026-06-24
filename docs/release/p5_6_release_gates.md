# SentinelFlow P5.6 Release Gates

- Gate version: P5.6-01
- Frozen: 2026-06-18
- Entry point: `scripts/p5_6_gates.sh`

## Gate Policy

P5.6 uses one fail-fast aggregate gate. Every required gate must pass on the
same commit and supported environment. A missing required tool, skipped test,
invalid Manifest, or non-zero command is a failure.

The aggregate script supports Linux and macOS Bash. It creates only temporary
test workspaces through the reused test suites and does not require real
targets. **P7 之前不实现真实资产发现和真实扫描。**

## Mandatory Gates

| ID | Gate | Command/evidence | Pass condition |
| --- | --- | --- | --- |
| P56-G01 | Rust formatting | `cargo fmt --all -- --check` | No formatting diff. |
| P56-G02 | Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | No warning or error. |
| P56-G03 | Rust tests | `cargo test --workspace --all-features` | All unit, contract, and crate integration tests pass. |
| P56-G04 | CLI/API/Web consistency | `tests/e2e/p5_5_consistency.sh` | Shared fixtures have zero semantic differences for validation, plan, Policy, run, findings, report, and Audit. |
| P56-G05 | Plugin Manifest validation | Registry contract tests plus CLI validation of every `plugins/**/sentinelflow.tool.yaml` parent directory | Every discovered Manifest passes structure, semantics, compatibility, dependencies, and safety checks. |
| P56-G06 | Policy/Audit/Approval coverage | Policy crate tests and `tests/e2e/p5_5_security/run.sh` | Default deny, target boundary, high-risk Approval lifecycle, RBAC denial, critical Audit, parser rejection, and bypass attempts pass. |
| P56-G07 | Report redaction | `cargo test -p sentinelflow-report --all-features reports_redact_sensitive_evidence_and_error_text` | Sensitive fixture values do not appear in generated reports. |
| P56-G08 | Web unit smoke | `node --test crates/sentinelflow-api/web/*.test.js` | All checked-in Web JavaScript tests pass. |
| P56-G10 | Web Quick Run fixture-only scope guard | `node --test crates/sentinelflow-api/web/*.test.js` plus `node scripts/p5_6_scope_guard.js` | Production Web builder accepts only local fixture targets, rejects real targets and standard/deep modes, and generated TaskSpec contains no P7 forbidden tokens. |
| P56-G09 | Web/API basic smoke | `tests/e2e/p5_5_smoke.sh` | Console, login, plugin lifecycle, task flow, normalized result, report, Audit, and SSE smoke pass. |

`scripts/p5_6_gates.sh` is the canonical ordering and invocation. Existing
P5.5 suites are intentionally reused as frozen comparison evidence; renaming or
replacing them requires updating this document and preserving equivalent
coverage.

## Coverage Invariants

### CLI/API/Web

- The same Task Spec and fixtures must produce equivalent plan, Policy,
  terminal status/error, normalized findings, report, and Core Audit actions.
- Web must remain an API client. Browser code must not execute tools, access
  `.sentinelflow/`, or implement an alternate Policy decision engine.

### Manifest + Adapter + Parser

- Every plugin has a valid Manifest.
- Execution is selected from the Manifest and enters a controlled Adapter.
- Parser output enters the Normalizer and protocol Schema validation before
  persistence or reporting.
- Adding a plugin must not require a Core modification.

### Policy + Approval + Audit

- Missing authorization context denies execution.
- High/critical risk requires a valid approved Approval unless an explicitly
  documented policy permits it.
- Critical requested, allowed, denied, failed, normalized, cancelled,
  approved/rejected/expired, and report actions are auditable.
- Delivery-layer RBAC or UI checks never replace Core/Runtime Policy.

### Report Redaction

- Reports consume persisted normalized artifacts only.
- Known secret/password/token/credential fixture values are replaced.
- Adding a report or export path requires equivalent redaction tests.

### Web

- Static JavaScript behavior has Node tests.
- The API-backed smoke flow verifies the served Console and safe end-to-end
  workflow.
- P56-G10 checks the actual TaskSpec produced by
  `buildSimpleCheckTaskSpec({domain: "example.com", mode: "quick"})`; it does
  not grep source files, so the denylist in the test code cannot create a false
  failure.
- P5.6 completion must add stable browser-level smoke coverage; the baseline
  gate does not claim full browser automation.

## Required Environment

- Rust 1.85 toolchain with `rustfmt` and `clippy`.
- Python 3 for existing E2E drivers.
- Node.js with the built-in `node:test` runner.
- POSIX userland and Bash on Linux or macOS.

Docker is not required by the baseline aggregate gate. Deployment and
container-hardening tasks must additionally run their documented Compose and
deployment gates.

## Local Execution

```sh
scripts/p5_6_gates.sh
```

Individual diagnostics may be run using the commands in the table, but a
release decision requires the complete aggregate script.

## CI Adoption

The P5.6 CI workflow invokes `bash scripts/p5_6_gates.sh` from
`.github/workflows/ci.yml` rather than maintaining a second drifting command
list. The workflow also performs `cargo build --workspace --all-features`
before the aggregate gate and prints `P5_6_GATE=scripts/p5_6_gates.sh` as
release evidence.

The performance workflow remains independent for manual or scheduled release
evidence and is not part of ordinary CI.

## Failure Handling

When a gate fails, record:

1. gate ID and exact command;
2. failing test/file and standard error;
3. whether failure predates the P5.6 change;
4. proposed fix or explicit scope decision;
5. rerun evidence.

Do not mark P5.6 accepted with an unexplained skipped or failing mandatory gate.
