# SentinelFlow P5.5 Productization Audit

Date: 2026-06-14

Status: Audit complete, remediation not started in this task.

## Scope

This audit reviews the current SentinelFlow v1.0-rc readiness baseline after P5. It covers the Rust workspace, CLI, Core boundary, adapters, schema validation, runtime normalization, policy, audit, report generation, API service, Web Console, examples, tests, deployment artifacts, and release documentation.

This task intentionally does not implement P6 features and does not add real scanning, exploitation, brute force, authentication bypass, persistence, stealth probing, or attack-chain automation.

## Evidence Reviewed

- Workspace and crate layout under `crates/`.
- CLI command tree and execution paths in `sentinelflow-cli`.
- Core constants and shared schema/runtime/policy/report/store crates.
- API service and embedded Web Console in `sentinelflow-api`.
- Schemas under `schemas/v1alpha1/`.
- Example plugins under `plugins/examples/`.
- Python SDK under `sdk/python/`.
- Integration, fixture, and e2e tests under `tests/`.
- Deployment and release materials: `Dockerfile`, `compose.yaml`, `CHANGELOG.md`, `docs/v1rc-trial-guide.md`, `docs/release-v1.0-rc.md`, `docs/v1.0-rc-acceptance-report.md`.

Previously observed local gates for the current baseline passed before this audit document was added:

- `cargo fmt --all -- --check`
- `cargo build --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `tests/e2e/p5_5_smoke.sh`
- `docker compose config`
- `docker compose build sentinelflow-api`

## Readiness Summary

SentinelFlow is close to a local v1.0-rc candidate for controlled pilot use. The repository already has a coherent Rust workspace, safe example plugins, Command/Docker/HTTP/File Import adapter coverage, schemas, normalizer/report/audit/store foundations, an API service, an embedded Web Console, a Docker Compose deployment path, and a P5.5 smoke test that exercises the main API workflow.

The main productization risks are architectural and operational rather than missing headline features:

- API and CLI share behavior partly through CLI calls and partly through duplicated API logic, instead of a single Core service boundary.
- Policy and audit are strong around execution, but not consistently modeled for all user-visible operations such as planning, explain, cancellation, pause/resume, report/export, and read-only views.
- Web/API/CLI consistency is smoke-tested, but not yet proven by a single cross-surface contract suite over the same Task Spec and expected outputs.
- Development authentication and SSE token handling are acceptable for local trial, but need hardening before broader pilot exposure.
- Reports and exports can publish normalized evidence without a dedicated sensitivity/redaction gate.

## Subsystem Findings

| Area | Current State | Readiness | Notes |
| --- | --- | --- | --- |
| Workspace | Rust workspace and required crates exist. | Ready | Crate naming and product constants are aligned with SentinelFlow conventions. |
| CLI | Command tree is broad and includes init, config, plugin, tool, task, policy, approval, report, audit, and result export paths. | Mostly ready | `result normalize` remains not implemented. Some command actions lack audit events. |
| Core Boundary | Shared constants exist, but orchestration/application service logic is still spread across CLI and API. | Needs work | API should call a Core service facade rather than CLI internals or duplicated local helpers. |
| Schemas | v1alpha1 schema files and contract tests exist. | Ready | Continue treating schema validation as mandatory before normalization/reporting. |
| Registry | Plugin validate/install and safe examples exist. | Mostly ready | Manifest secret references are modeled; keep blocking plaintext credentials in manifests. |
| Adapters | Command, Docker, HTTP, and File Import adapters have examples and contract tests. | Mostly ready | Adapter execution should remain behind policy, audit, and normalizer wrappers. |
| Runtime/Normalizer | Finding/evidence normalization and deduplication paths exist. | Mostly ready | Add sensitivity/redaction gate before persistence/report/export. |
| Policy | Default-deny model and policy explain paths exist. | Mostly ready | Execution policy exists, but plan/create/report/export semantics are not centralized. |
| Audit | API and execution paths record many key events. | Needs work | Cancellation, pause/resume, some CLI reads, plan/explain, and report/export coverage should be made explicit. |
| Store | SQLite store with migration helpers and failure tests exists. | Mostly ready | Versioned migration metadata and recovery guidance are still thin. |
| Report | Report generation and markdown output exist. | Mostly ready | Report failure and sensitive evidence handling need stronger tests. |
| API | Auth/RBAC, plugin/task/tool/report/audit endpoints, SSE logs, OpenAPI, and tests exist. | Mostly ready | API contains duplicated application logic and query-token SSE risk. |
| Web Console | Single-page console can drive the local workflow through API calls. | Mostly ready | Needs browser-level e2e and stronger auth/session handling for pilot exposure. |
| E2E | `tests/e2e/p5_5_smoke.sh` covers the core API workflow. | Partial | It is HTTP-level, not full Web UI automation, and does not compare CLI/API/Web outputs. |
| Deployment | Dockerfile, Compose, health endpoint, release/trial docs exist. | Mostly ready | Runtime image and operational hardening can be improved. |
| Release Docs | Changelog, trial guide, release notes, acceptance report exist. | Ready | Keep updating as fixes land. |

## Security Boundary Audit

| Requirement | Result | Notes |
| --- | --- | --- |
| No real scanning/exploitation/bruteforce behavior | Pass | Examples are controlled mock/safe adapters and fixture-driven flows. |
| Web must not bypass API/Core | Pass with architectural caveat | Web uses API endpoints. The caveat is API/Core boundary, not Web direct execution. |
| API must not duplicate Core logic | At risk | API owns helper logic for registry/task/report/approval/policy paths and calls CLI internals for execution. |
| Adapter must not bypass Policy/Audit/Normalizer | Mostly pass | Execution paths wrap adapters through CLI orchestration; keep this invariant in Core facade tests. |
| Default deny | Pass | Policy docs and tests reflect default-deny behavior. |
| Critical actions audited | Partial | Execution and API actions are covered; cancel/pause/resume and some planning/read/report/export paths need explicit coverage. |
| Outputs schema-validated and normalized | Mostly pass | Execution outputs are normalized; report/export sensitivity handling needs hardening. |
| Secrets not in manifests | Mostly pass | HTTP adapter uses `secretRef`; add stricter negative tests for plaintext credential patterns. |
| Dev credentials not production-safe | Known risk | Docs use local demo tokens; startup/config should make non-production status unmistakable. |
| Plugin isolation | Pass for current phase | Plugins execute as external process/container/import adapter flows, not in-process untrusted dynamic libraries. |

## Priority Summary

| Priority | Count | Meaning |
| --- | ---: | --- |
| Blocker | 0 | No issue was found that prevents continued local v1.0-rc hardening work. |
| High | 6 | Must fix before a broader pilot or public rc candidate. |
| Medium | 8 | Should fix or explicitly accept before v1.0-rc sign-off. |
| Low | 5 | Polish, documentation consistency, and release hygiene. |

## Blocker Issues

None found during this audit.

This does not mean the product is ready for broad external use. It means no single issue currently blocks continuing the v1.0-rc hardening track in this repository.

## High Issues

### P55-H01: Core/API/CLI application boundary is not clean enough

API behavior is partly implemented by API-local helpers and partly by calling CLI execution functions. This makes it harder to prove CLI/API/Web consistency and risks future divergence.

Impact: Core architecture, API service, CLI, Web workflow, tests.

Recommended fix: Introduce a Core application service facade for plugin validation/install, task plan/run/cancel/status/logs, policy explain, approval, report, and audit query operations. CLI and API should both call this facade.

### P55-H02: Audit coverage is incomplete for lifecycle and read/planning operations

Execution and many API actions are audited, but task cancellation, pause/resume, some CLI plan/explain/read operations, and report/export flows need explicit audit guarantees.

Impact: Audit, CLI, API, task lifecycle, compliance trail.

Recommended fix: Define an audit event matrix and add tests proving every required user-visible operation writes the expected event.

### P55-H03: Policy checks are not centralized across all product operations

Execution policy is present, but policy semantics for task creation/plan, policy explain, report generation, result export, and audit/report visibility are not represented through one central authorization/policy gate.

Impact: Policy, API, CLI, report/export, Web consistency.

Recommended fix: Add a shared authorization and policy preflight layer in Core, with operation-specific policy decisions and tests for denied paths.

### P55-H04: SSE log streaming accepts token in query string

The documented and Web-used SSE path supports `token=` in the URL. Bearer-like tokens in URLs can leak through browser history, referrers, reverse proxies, logs, screenshots, and diagnostics.

Impact: API, Web Console, logs, deployment security.

Recommended fix: Replace query tokens with short-lived stream tickets or cookie/session-based auth. Redact query strings in request logs.

### P55-H05: Reports and exports lack a dedicated sensitivity/redaction gate

Normalized findings and evidence can be persisted and reported. If a future adapter or parser emits secrets in evidence fields, the report/export path may publish them unless a redaction policy is enforced.

Impact: Normalizer, report, result export, API, CLI.

Recommended fix: Add sensitivity classification/redaction before persistence and before report/export rendering, with tests using synthetic secret-like fixture values.

### P55-H06: Cross-surface consistency is not yet proven as a release gate

The smoke test exercises the API workflow, and CLI/API code paths share pieces of implementation. There is not yet a single contract test that drives CLI, API, and Web against the same Task Spec and compares plan, policy explain, run, findings, report, and audit outcomes.

Impact: CLI, API, Web, e2e release gate.

Recommended fix: Add a P5.5 consistency suite with the same safe fixture executed across CLI/API/Web surfaces and stable expected normalized outputs.

## Medium Issues

### P55-M01: OpenAPI coverage is useful but not yet release-grade

OpenAPI documentation exists, but request/response schemas, error payloads, status codes, SSE behavior, and role requirements need stronger completeness.

### P55-M02: Store migrations need explicit versioning and recovery documentation

The store has migration helpers and failure tests. A release candidate should also expose schema version tracking, startup diagnostics, and recovery guidance for migration failures.

### P55-M03: Web Console lacks browser-level e2e coverage

The existing P5.5 smoke test is HTTP-level. It does not prove the browser UI workflow from login through report/audit.

### P55-M04: Development identity provider needs stronger production guardrails

Local demo tokens are documented and useful for trial. The API should make development-auth mode explicit at startup and hard to expose accidentally on shared networks.

### P55-M05: Scheduler concurrency and rate-limit state is process-local

The current scheduler is appropriate for single-node local deployment. It is not crash-proof and should be documented or guarded as a v1.0-rc limitation.

### P55-M06: Docker runtime image is heavier than needed

The current Docker build is serviceable for local trial, but a slimmer runtime image and clearer non-root/runtime hardening would improve deployment confidence.

### P55-M07: `result normalize` remains not implemented

The command exists in the CLI tree but returns NotImplemented. This is acceptable only if release notes clearly mark it outside v1.0-rc behavior.

### P55-M08: Error model consistency needs one more pass

CLI exit codes are defined, and API errors exist. Expected schema, policy, runtime, report, and system failures should consistently map to standard error codes and HTTP responses.

## Low Issues

### P55-L01: Release documentation is split between root docs and release folder

Release material currently lives in `docs/` and now `docs/release/`. This is workable, but a release index would improve discoverability.

### P55-L02: Generated local artifacts appear under source directories

Python `__pycache__` files are present under `sdk/python/`. They should be ignored or cleaned before release packaging.

### P55-L03: Some security-boundary examples appear older than current plugin set

Security docs mention a smaller allowlist/example set than the current safe example catalog. Update wording to avoid stale interpretation.

### P55-L04: Web Console testability hooks are thin

The console is usable, but browser e2e would be easier with stable selectors and smaller UI components.

### P55-L05: Release gate command wording should be normalized

Some docs use `cargo clippy --workspace --all-targets`; release gates should consistently include `-- -D warnings` when that is the intended rc standard.

## Recommended Release Gate Before v1.0-rc

The next release gate should require:

1. `cargo fmt --all -- --check`
2. `cargo build --workspace`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo test --workspace`
5. `tests/e2e/p5_5_smoke.sh`
6. A new CLI/API/Web consistency suite.
7. A new audit matrix test suite.
8. A new security negative suite for policy denial, unauthorized access, parser invalid output, report failure, migration failure, cancellation, SSE disconnect, and synthetic secret redaction.

