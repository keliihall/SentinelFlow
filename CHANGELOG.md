# Changelog

## v1.0-rc - Unreleased

### Added

- API Service and Web Console for local team trials.
- Replaceable identity-provider interface with local development sessions.
- Minimal RBAC roles: `viewer`, `operator`, `approver`, and `admin`.
- OpenAPI document at `/openapi.json`.
- SSE task audit log stream with reconnect cursor.
- Single-machine deployment via `Dockerfile` and `compose.yaml`.
- P5.5 e2e smoke test covering plugin validation, installation, planning,
  policy explain, execution, logs, findings, reports, and audit.
- P5.5 CLI/API/Web consistency fixtures, e2e runner, and release consistency
  report.
- Safe `example-invalid-parser` plugin for parser/normalizer negative tests.
- P5.5 full-flow E2E scenarios for low-risk execution, high-risk approval,
  mixed failure reporting, and task cancellation.
- Safe `example-restricted-high-risk` plugin for approval E2E tests.
- P5.5 security hardening E2E and release security hardening report.
- P5.5 reliability/recovery E2E and release reliability report.
- P5.5 deployment/upgrade E2E, deployment docs, config examples, and release
  deployment report.
- P5.5 performance baseline script, raw metrics output, and release capacity
  baseline report.
- P5.5 documentation usability pass covering README, quick start, Web Console,
  protocol resources, plugin development, troubleshooting, and safe examples.
- v1.0-rc trial guide and acceptance report.
- v1.0-rc release gate report, known issues register, and release notes for
  controlled pilot sign-off.
- GitHub Actions release gates for fmt, build, clippy with `-D warnings`, tests,
  and P5.5 smoke/consistency/full-flow/security/reliability/deployment E2E.
- Manual and scheduled GitHub Actions performance baseline workflow.
- Planning/task-book material is archived under `docs/planning/` so the main
  documentation index stays focused on trial, deployment, protocol, security,
  troubleshooting, and release artifacts.

### Hardened

- API contract tests now cover authentication, RBAC, CLI/API plan consistency,
  high-risk approval, target authorization denial, time-window denial, plugin
  execution failure, parser invalid output, report failure, audit recording, and
  SSE reconnect behavior.
- Store tests now cover controlled database initialization failure.
- Store migration metadata now records the current SQLite schema version and
  rejects newer unsupported schemas explicitly.
- Store tests now cover report artifact and audit write failures.
- Task state transitions now emit `task.state.*` audit events and persist
  `lastError` on blocked or failed tasks.
- API rejects duplicate run requests while a same-name task is active.
- API task-log SSE `limit` now applies to emitted events, enabling deterministic
  reconnect windows without duplicate historical events.
- API list endpoints for tasks, runs, findings, reports, approvals, audit, and
  task logs now apply default page limits and accept `limit`/`offset`.
- SQLite schema version 3 adds audit/task-log pagination indexes and audit
  append writes to avoid rewriting the full audit log for every event.
- API report generation now enforces the v1.0-rc finding-count guard before
  loading large report bundles.
- Dependency lockfile is constrained so fresh Rust 1.85 container builds do not
  resolve ICU/idna crates requiring Rust 1.86.
- API error responses now include a stable standard error `code`, preserving
  CLI/Core error kinds for Web and HTTP clients.
- API report generation now emits the shared `report.generated` audit action in
  addition to the API-layer audit action.
- Task cancellation now emits the shared `task.cancel.requested` audit action.
- API login and selected denied RBAC attempts now emit Audit Events.
- Preflight task Policy denial now emits `policy.denied` before returning.
- Preflight approval-required denials now persist `approvalRequired` task state
  instead of leaving tasks in planning.
- Markdown reports redact sensitive-looking target, finding, evidence, and error
  content during rendering.
- CI now pins the Rust toolchain to the declared `1.85.0` baseline instead of
  floating on latest stable.
- CI and performance workflows now have explicit 30-minute job timeouts.

### Security

- Web Console remains an API-only client and does not execute tools directly.
- API task execution reuses the existing SentinelFlow CLI/Core orchestration path.
- No real scanner, exploit, brute-force, stealth, persistence, bypass, or attack
  automation capability was added.

## 0.1.0 - Engineering Baseline

- Rust workspace baseline.
- CLI, protocol, adapters, policy, audit, reports, DAG orchestration, API service,
  and minimal Web Console foundations.
