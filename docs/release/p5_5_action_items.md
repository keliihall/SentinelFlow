# SentinelFlow P5.5 Action Items

Date: 2026-06-14

Status: Open backlog for v1.0-rc hardening.

Priority definitions:

- Blocker: must be fixed before continuing toward v1.0-rc.
- High: must be fixed before broader pilot or public rc candidate.
- Medium: should be fixed or explicitly accepted before v1.0-rc sign-off.
- Low: release polish, documentation consistency, or hygiene.

## Action Item Table

| ID | Priority | Description | Impact Scope | Fix Recommendation | Acceptance Method | Associated Test |
| --- | --- | --- | --- | --- | --- | --- |
| P55-H01 | High | Core/API/CLI application boundary is not clean enough; API duplicates some application logic and also calls CLI execution paths. | Core, CLI, API, Web, tests | Add a `sentinelflow-core` application service facade for plugin, task, policy, approval, report, audit, and result operations. Make CLI and API call the facade. | Code review confirms API no longer calls CLI internals for business operations and does not duplicate orchestration/report/policy helpers. | `cargo test --workspace core_service_consistency`; add CLI/API parity tests for plan/run/report/audit. |
| P55-H02 | High | Audit coverage is incomplete for cancel, pause, resume, plan/explain/read, report, and export operations. | Audit, CLI, API, task lifecycle, compliance | Define an audit event matrix and implement missing events through shared Core operations. | Every required operation has an audit event with action, actor/source, subject, outcome, and stable schema validation. | New `tests/integration/audit_matrix.rs`; extend `tests/e2e/p5_5_smoke.sh` to assert cancel/pause/resume/report/export audit events. |
| P55-H03 | High | Policy checks are not centralized across all product operations. | Policy, Core, CLI, API, Web, report/export | Add a shared authorization/policy preflight function for task create/plan/run/report/export/audit visibility. | Unauthorized or policy-denied operations fail with standard error model and do not mutate state except audit denial events. | New `tests/integration/policy_operation_gate.rs`; API tests for report/export denial. |
| P55-H04 | High | SSE log streaming accepts bearer-like token in URL query string. | API, Web, logs, deployment security | Replace query tokens with short-lived stream tickets or cookie/session auth; redact URL query strings from logs. | Web log streaming works without persistent token in URL; unauthorized streams are rejected; logs do not contain token values. | API SSE auth test plus Web smoke assertion for stream ticket flow. |
| P55-H05 | High | Report/export paths lack a dedicated sensitivity and redaction gate for normalized evidence. | Normalizer, report, result export, CLI, API | Add sensitivity classification and redaction policy before persistence and before rendering report/export. | Synthetic secret-like values are redacted in stored report/export while preserving non-sensitive finding fields. | New fixtures under `tests/fixtures/security/`; `tests/integration/report_redaction.rs`. |
| P55-H06 | High | CLI/API/Web consistency is not yet a release gate over the same Task Spec. | CLI, API, Web, e2e release gate | Add a P5.5 consistency suite that runs one safe Task Spec through CLI, API, and Web and compares plan, policy explain, run, findings, report, and audit. | Suite produces deterministic normalized outputs and fails on cross-surface drift. | New `tests/e2e/p5_5_consistency.sh` plus browser-level Web test. |
| P55-M01 | Medium | OpenAPI coverage is not yet release-grade for schemas, errors, SSE, and RBAC metadata. | API docs, SDK consumers, Web integration | Expand OpenAPI with request/response schemas, standard errors, status codes, role requirements, and SSE notes. | OpenAPI validates and documents every public P5 endpoint used by the Web Console. | API documentation contract test comparing routes to OpenAPI paths. |
| P55-M02 | Medium | Completed in P5.5-06: Store migrations now have explicit SQLite version metadata, idempotent upgrade tests, newer-schema failure handling, and recovery guidance. | Store, deployment, release operations | Keep migration metadata and recovery docs current as schemas evolve. | Fresh and upgraded stores report schema version; forced migration failure has clear error; deployment report records upgrade preservation. | `cargo test -p sentinelflow-store`; `tests/e2e/p5_5_deployment/run.sh`; `docs/release/p5_5_deployment_report.md`. |
| P55-M03 | Medium | Web Console lacks browser-level e2e coverage for the full workflow. | Web, API, release confidence | Add browser automation for login, plugin validate/install, tool view, Task Spec edit, plan, policy explain, approval, run, logs, findings, report, and audit. | Browser e2e passes on a clean local Compose/API setup without direct store access. | New browser e2e test script or Playwright test under `tests/e2e/`. |
| P55-M04 | Medium | Development identity provider needs stronger production guardrails. | API auth, deployment docs, operations | Add explicit dev-auth startup warning and require intentional config for non-local binding. | API refuses or warns clearly when demo auth is used outside local trial mode. | API config tests for local/dev/prod auth modes. |
| P55-M05 | Medium | Scheduler concurrency and rate-limit state is process-local and not crash-proof. | Runtime, orchestrator, store, docs | Document v1.0-rc single-node limitation; persist enough state to recover or mark interrupted runs safely. | Restart during a run leaves tasks in a deterministic cancelled/failed/recoverable state. | New restart/recovery integration test with temporary workspace. |
| P55-M06 | Medium | Docker runtime image is heavier and less hardened than ideal. | Deployment, release packaging | Use a slimmer runtime stage, run as non-root, document mounted workspace permissions, keep healthcheck. | `docker compose build` and smoke test pass with non-root runtime image. | `docker compose build sentinelflow-api`; `tests/e2e/p5_5_smoke.sh` against container. |
| P55-M07 | Medium | `result normalize` remains NotImplemented in the CLI tree. | CLI UX, docs, result workflow | Either implement fixture-only normalization through the existing normalizer or document it as excluded from v1.0-rc. | Command behavior and docs agree; NotImplemented is not surprising to users. | CLI command test for `result normalize` expected behavior. |
| P55-M08 | Medium | Error model consistency needs a pass across CLI and API. | CLI, API, Web, docs | Map schema, policy, runtime, report, system, and parameter failures to stable exit codes and HTTP statuses. | Negative tests assert standard error code, message shape, and no panic for each class. | New `tests/integration/standard_error_matrix.rs`; API negative route tests. |
| P55-L01 | Low | Release documentation is split between `docs/` root and `docs/release/`. | Docs, release handoff | Add a release index or move release-only materials into `docs/release/` with redirects/links. | New users can find trial guide, release notes, acceptance report, audit, and action items from one index. | Markdown link check for release docs. |
| P55-L02 | Low | Generated local artifacts such as Python `__pycache__` appear under source directories. | Release hygiene, packaging | Add or verify ignore rules and clean generated artifacts before packaging. | Release package excludes generated caches and local runtime output. | Packaging dry-run or file allowlist test. |
| P55-L03 | Low | Security-boundary docs mention older example allowlist language. | Docs, security expectations | Update wording to describe current safe example categories rather than a stale fixed list. | Security docs match current safe example catalog and keep default-deny language. | Markdown/doc review; optional doc test checking example names. |
| P55-L04 | Low | Web Console testability hooks are thin. | Web, e2e maintainability | Add stable selectors for key workflow controls and outputs. | Browser e2e can target stable selectors instead of brittle text/DOM structure. | Browser e2e selector smoke test. |
| P55-L05 | Low | Release gate command wording is not fully normalized. | Docs, release process | Use one canonical gate list including `cargo clippy --workspace --all-targets -- -D warnings`. | README, release notes, trial guide, and acceptance report agree on gate commands. | Markdown grep/link check for release gate command list. |

## Suggested Execution Order

1. Fix P55-H01 first so later policy, audit, API, CLI, and Web tests attach to one Core boundary.
2. Fix P55-H02 and P55-H03 together because audit and policy should be enforced by the same operation layer.
3. Fix P55-H04 and P55-H05 before exposing the API/Web Console beyond a local trusted trial.
4. Add P55-H06 as the release gate that proves the previous fixes did not drift across surfaces.
5. Work through Medium items before declaring v1.0-rc ready for pilot.
6. Complete Low items before packaging release artifacts.

## Current Release Recommendation

Do not move to P6 yet.

Continue P5.5 hardening. The current baseline is suitable for local controlled validation, but broader v1.0-rc pilot readiness should wait until the High items are closed or formally risk-accepted.
