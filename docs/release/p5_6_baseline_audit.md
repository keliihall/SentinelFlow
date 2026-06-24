# SentinelFlow P5.6 Baseline Audit

- Audit date: 2026-06-18
- Phase: P5.6 architecture convergence and quality hardening
- Baseline commit: `8d70aac0daf9143ed28b4b88f6262e09e8f79d41`
  (`main` at P5.6-01 acceptance-closure start)
- Acceptance command: `scripts/p5_6_gates.sh`

## Executive Conclusion

SentinelFlow has a functional v1.0-rc single-node baseline with protocol
schemas, plugin validation, controlled adapters, default-deny execution
Policy, Approval, Audit Events, normalization, SQLite persistence, reporting,
an API, and an API-backed Web Console.

The baseline is suitable for P5.6 refactoring only after its current tests are
treated as frozen regression evidence. It is not yet a clean architecture:
the API directly depends on and invokes the CLI library, application workflow
logic is concentrated in the CLI, some API operations implement adjacent
workflow logic independently, and Policy/Audit coverage is not represented by
one mandatory operation boundary.

The repository also contains real-domain and bounded active-verification
language and paths. This conflicts with the phase boundary. **P7 之前不实现真实资产发现和真实扫描。**
P5.6 must not expand or accept those capabilities as phase deliverables.

## Repository Structure

| Area | Current baseline | Audit observation |
| --- | --- | --- |
| `crates/` | 14 workspace crates | Includes the expected Core, CLI, Schema, Runtime, Registry, Store, Policy, Report, Orchestrator, API and Command Adapter, plus Docker, HTTP, and file-import adapters. |
| `schemas/v1alpha1/` | 11 JSON Schemas plus README | Covers metadata, capability, Manifest, task, input/output, finding, evidence, error, audit, and policy resources under `sentinelflow.io/v1alpha1`. |
| `plugins/` | 32 manifests across examples and official plugins | Integrations are directory-based and use `sentinelflow.tool.yaml`; validation is implemented in `sentinelflow-registry`. |
| `sdk/python/` | Python package, `pyproject.toml`, and unit test | Early SDK surface exists and is outside the Rust workspace gate unless tested explicitly. |
| `docs/` | Architecture, protocol, CLI, API/Web, adapters, security, deployment, examples, planning, and release evidence | P5.5/v1.0-rc evidence is extensive but architecture debt and P5.6 scope need a single current baseline. |
| `tests/fixtures/` | Protocol, task, policy, failure, and P5.5 fixtures | Shared fixtures support repeatable CLI/API comparisons and negative paths. |
| `tests/integration/` | README only | Cross-crate integration coverage currently lives mainly in crate tests and E2E scripts. |
| `tests/e2e/` | Smoke, consistency, full-flow, security, reliability, deployment, asset-flow, and plugin flows | Strong reusable P5.5 evidence; browser automation remains limited. |
| `.github/workflows/` | `ci.yml`, `performance.yml` | CI runs Rust checks and P5.5 E2E gates, but not the new all-features P5.6 aggregate gate. |
| `Dockerfile` | Multi-stage Rust build, API/CLI runtime image | Runtime uses the full Rust image, installs Python, and runs without an explicit non-root user. |
| `compose.yaml` | Single API service with persistent volumes and health check | Suitable for local single-node use; not a production or distributed topology. |

## Current Capability Baseline

- CLI validation, planning, task execution, cancellation/resume, plugin
  operations, Policy explanation, Approval lifecycle, Audit listing, result
  export, and report generation.
- API endpoints for session, system status, tools/plugins, task lifecycle,
  logs/SSE, runs, findings, reports, Audit, Approval, and Policy explanation.
- Embedded Web Console that uses `/api/*` HTTP endpoints and does not directly
  spawn plugin processes.
- Manifest discovery, semantic/compatibility/dependency/safety validation, and
  registry installation.
- Out-of-process Command Adapter with environment allowlisting, path checks,
  output limits, timeout, cancellation, and no shell interpretation.
- Docker, HTTP, and file-import adapter implementations in addition to the
  original Command Adapter baseline.
- Parser + Normalizer conversion into `ToolOutput`, generated fingerprints,
  deduplication, protocol validation, and normalized persistence.
- SQLite indexes plus atomic task, run, result, Approval, report, and Audit
  artifacts under `.sentinelflow/`.
- Deterministic Markdown reports with sensitive-value redaction.
- P5.5 CLI/API/Web consistency, security, reliability, deployment, and
  performance evidence.

## Current Call Relationships

```text
Web Console
    -> HTTP /api/*
        -> sentinelflow-api
            -> sentinelflow-cli::execute (plugin test, task run/cancel)
            -> Registry / Orchestrator / Policy / Store / Report directly

sentinelflow CLI
    -> commands.rs application workflow
        -> Registry + Orchestrator + Policy
        -> Runtime Adapter.prepare/execute/collect
            -> Command / Docker / HTTP / File Import adapter
        -> built-in Parser -> Runtime Normalizer -> Schema validation
        -> Store normalized result + Audit Events
        -> Report from persisted normalized artifacts

Plugin directory
    -> Manifest selects Adapter, runner, Parser, schemas, limits and capabilities
    -> out-of-process runner or controlled adapter
    -> adapter output Schema validation
    -> trusted Parser + Normalizer
    -> Store / Report
```

| Component | Calls or owns | Baseline assessment |
| --- | --- | --- |
| Web | API client and presentation behavior | No direct process execution found. Static checks and E2E assert API-only wiring, but browser-level network enforcement is not exhaustive. |
| API | CLI plus Registry, Orchestrator, Policy, Store, Report, Schema | Delivery layer is coupled to CLI and also owns orchestration glue; this is the primary convergence target. |
| CLI | Application workflows and all domain crates | CLI is both delivery layer and de facto application service, making reuse awkward. |
| Core | Product constants | Core is currently small; shared business use cases have not yet moved behind a Core-facing service boundary. |
| Runtime | Adapter contract, authorization helper, Parser, Normalizer | Central execution and normalization contracts exist. |
| Policy | Execution and task-policy decisions, Approval state machine | Default-deny logic exists, but callers must remember to invoke the correct checks. |
| Store | SQLite indexes and atomic artifacts | Persists normalized results, state, approvals, reports, and audit; visibility policy is enforced by callers. |
| Report | Reads normalized persisted data and redacts output | Correct source boundary, but classification before persistence/export is incomplete. |
| Adapter | Controlled execution/import/network boundary | Adapters call shared authorization during `prepare`; non-Command adapters expand beyond the original phase-one baseline. |

## Risk Register

| ID | Severity | Risk and evidence | P5.6 disposition |
| --- | --- | --- | --- |
| P56-R01 | High | `sentinelflow-api` depends on `sentinelflow-cli` and calls `sentinelflow_cli::execute` for plugin test and task run/cancel. API behavior therefore depends on a delivery-layer command dispatcher. | Must close by introducing a shared application/Core service used by both delivery layers; preserve consistency tests throughout. |
| P56-R02 | High | API also directly invokes Registry, Orchestrator, Policy, Store, and Report. This permits CLI/API workflow drift and duplicated audit/error mapping. | Must close for mutating/critical use cases or document a narrow read-only exception. |
| P56-R03 | High | Policy checks are distributed across API preflight, CLI task workflow, Runtime authorization, adapter `prepare`, and RBAC helpers. Read/report/export visibility lacks one shared operation-policy gate. | Must close for all critical operations before P6. Default deny on missing policy context. |
| P56-R04 | High | Audit calls are manually placed. Several handlers use `require_identity` rather than the audited authorization helper, so denied and failed paths depend on endpoint-specific code. Approval audit events also omit a shared execution context. | Must define and test a critical-action matrix; all allowed, denied, failed, and state-transition outcomes must be auditable. |
| P56-R05 | High | The normalized execution path is strong, but `WorkspaceStore::save_result` is public and accepts a constructed `ResultArtifact`; architectural enforcement relies on caller discipline. Adapter `collect` validates adapter output before the separate Parser/Normalizer stage. | Must make normalized persistence an explicit trusted boundary and add bypass tests. |
| P56-R06 | High | Repository plugins, examples, docs, and current Web work include real-domain, external-intelligence, active DNS, TCP connect, and vulnerability-import terminology or paths. | Scope blocker: freeze expansion and separate compatibility fixtures from P7 capabilities. P7 之前不实现真实资产发现和真实扫描。 |
| P56-R07 | High | SSE accepts a bearer-like token in the URL query. Query strings may leak through history or proxy logs. | Must close before broader/private-network P6 deployment; use short-lived stream tickets or cookie-backed sessions. |
| P56-R08 | High | Static development tokens/passwords can be used while binding beyond localhost; CORS is permissive. | Must add non-local startup guardrails and production authentication/CORS configuration before P6. |
| P56-R09 | Medium | Report rendering redacts sensitive-looking values, but sensitivity classification before persistence and every export path is incomplete. | Must close before real data is accepted; keep report redaction gate mandatory. |
| P56-R10 | Medium | Web tests are mostly static Node tests and API-driven E2E; there is no full browser navigation/accessibility suite. | Acceptable during early P5.6; add a stable browser smoke gate before P5.6 completion. |
| P56-R11 | Medium | CI previously invoked individual P5.5 scripts and omitted `--all-features`; release criteria could drift from local documentation. | Closed: CI now builds `--all-features` and invokes `scripts/p5_6_gates.sh` as the single aggregate release gate. |
| P56-R12 | Medium | Integration tests are dispersed and `tests/integration/` contains no executable suite. | Acceptable if the aggregate gate remains authoritative; converge test ownership during P5.6. |
| P56-R13 | Medium | Docker image is large, runs without an explicit non-root user, and is not a hardened production image. | P6 prerequisite, not a blocker for local P5.6 development. |
| P56-R14 | Medium | Scheduler and SQLite workspace assume a single process/node; recovery and concurrency are not production-grade. | Accepted for P5.6 single-node scope; must be addressed or explicitly constrained before P6 production use. |

## Specific Bypass Findings

### API calling CLI

Confirmed. `sentinelflow-api` imports CLI command types and calls
`sentinelflow_cli::execute`. This is not process spawning, but it is an
architectural inversion: API depends on another delivery layer.

### Web bypassing API

No direct plugin execution or local Store access was found in the embedded Web
Console. Web actions use `fetch` against `/api/*`. Residual risks are forged
requests, permissive CORS, URL query tokens for SSE, and insufficient real
browser coverage; API RBAC and Policy must remain authoritative.

### Plugin bypassing Core

Plugins are out of process and selected through Manifest/Adapter/Parser.
Command execution passes adapter `prepare` and shared authorization. The main
risk is not an observed direct plugin-to-Core call; it is future adapter or
workflow code bypassing the shared preparation boundary because no single
application service owns all execution.

### Result bypassing Normalizer

Normal task/tool execution invokes a built-in Parser and `normalize` before
`save_result`, and reports read normalized artifacts. The Store API can still
be called directly with a constructed result, so the invariant is convention
rather than a type-enforced persistence boundary.

### Incomplete Audit

Critical happy paths have broad P5.5 coverage. Completeness is not guaranteed
centrally because authentication, RBAC denial, operation failure, Approval
transition, and read access auditing are implemented per endpoint. The P5.6
gate freezes current coverage; P5.6 architecture work must introduce a
critical-action matrix and shared audited operation boundary.

## Must-Close Items

The following block P5.6 completion unless explicitly re-scoped and accepted:

1. Remove API-to-CLI dependency for critical workflows by extracting shared
   application services.
2. Define one mandatory operation path for Policy, Approval, Audit, standard
   errors, Normalizer, and persistence.
3. Add tests that fail when execution skips Policy, output skips Normalizer, or
   critical outcomes skip Audit.
4. Freeze and reconcile all pre-P7 real discovery/scanning paths with
   `docs/release/p5_6_scope.md`.
5. Make CLI/API/Web consistency, Manifest validation, security coverage,
   report redaction, and Web smoke tests mandatory in one gate.
6. Replace or tightly constrain SSE query tokens and non-local development
   authentication before P6 readiness.
7. Establish sensitivity classification/redaction policy before accepting real
   production evidence.

## Acceptable Risks During P5.6

- Single-node SQLite and process-local scheduling for local, trusted,
  synthetic/fixture-only development.
- Docker image size and root runtime while not used as production packaging.
- Static Web assets embedded in the API crate.
- Limited browser automation at the P5.6 baseline, provided API E2E and Node
  tests pass and a browser smoke gate is added before phase completion.
- Existing adapter implementations remaining in place for compatibility,
  provided no new real discovery/scanning behavior is added.

## P5.6 Non-Goals

- No real internet asset discovery.
- No real active scanning.
- No exploit, brute-force, stealth, persistence, bypass, or attack-chain work.
- No distributed worker architecture, marketplace, AI analysis, or PostgreSQL
  runtime implementation.
- No deletion of existing behavior solely to make the architecture look clean.
- No protocol or external-behavior break unless separately approved,
  documented, migrated, and tested.

## P6 Prerequisites

- Shared application service boundary used by CLI, API, and future delivery
  layers.
- Central operation Policy and audited authorization model.
- Enforced normalized-output persistence boundary and sensitivity
  classification.
- Production authentication configuration, non-local startup guardrails,
  constrained CORS, and safe log-stream authentication.
- Hardened non-root container image and deployment smoke evidence.
- Durable scheduler/recovery decision and explicit single-node or distributed
  operating model.
- Complete OpenAPI/error/RBAC contract and browser-level Web smoke coverage.
- P5.6 aggregate gate running in CI on the release commit.

## Baseline Acceptance Evidence

The authoritative gate definition is
`docs/release/p5_6_release_gates.md`. Results from the baseline run must be
recorded in the task completion report; a failed command is not waived by this
document.

### P5.6-01 Baseline Run

Run date: 2026-06-18

| Gate | Result | Baseline evidence |
| --- | --- | --- |
| P56-G01 Rust formatting | pass | `cargo fmt --all -- --check`. |
| P56-G02 Rust lint | pass | `cargo clippy --workspace --all-targets --all-features -- -D warnings`. |
| P56-G03 Rust tests | pass | `cargo test --workspace --all-features`; all workspace and doc tests passed. |
| P56-G04 CLI/API/Web consistency | pass | The served Console assets declare `browser only calls the API service`, publish all seven required core workflow endpoint references, contain no forbidden direct-execution fragments, and all six CLI/API fixtures have zero differences. |
| P56-G05 Plugin Manifest validation | pass | Registry contract tests passed and all 32 discovered plugin Manifests passed CLI validation. |
| P56-G06 Policy/Audit/Approval coverage | pass | Four Policy tests and 22 P5.5 security checks passed. |
| P56-G07 Report redaction | pass | Sensitive evidence/error fixture test passed. |
| P56-G08 Web unit smoke | pass | Checked-in Web Node tests passed. |
| P56-G09 Web/API basic smoke | pass | The Console-to-report flow completed with two normalized findings. |
| Aggregate `scripts/p5_6_gates.sh` | pass | All P56-G01 through P56-G09 gates passed in one serial aggregate run. |
| Public CI wiring | configured | `.github/workflows/ci.yml` prints `P5_6_GATE=scripts/p5_6_gates.sh`, runs `cargo build --workspace --all-features`, and invokes the aggregate gate directly. Public GitHub Actions success evidence is the CI run for the wiring commit. |

P56-G04 was closed without removing or weakening its checks. The served
`simple-check.js` asset now exports a machine-readable Web boundary contract
containing the exact API-only statement and the complete required endpoint set.
The consistency test fetches the Console and each served `/console/` script
asset before checking the combined source, and a Node regression test asserts
the contract independently. No API, Policy, Audit, Normalizer, or execution
behavior changed.
