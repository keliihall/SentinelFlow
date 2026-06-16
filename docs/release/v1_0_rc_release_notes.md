# SentinelFlow v1.0-rc Release Notes

Generated: 2026-06-15T05:13:31Z
Updated: 2026-06-16T01:26:53Z

## Release Summary

SentinelFlow v1.0-rc is a controlled pilot candidate for a network security
validation tool management framework. It provides a unified way to validate,
register, plan, execute, normalize, report, and audit safe external tool
workflows.

This release does not add scanner, exploit, brute-force, stealth probing,
authentication bypass, persistence, or attack-chain automation capabilities.

## Pilot Readiness

The v1.0-rc release gate is split between default GitHub Actions CI and a
manual/scheduled performance workflow:

- Default CI runs build, format, Clippy, full workspace tests, CLI/API/Web
  consistency, full Web/API flow, security, reliability, and deployment E2E.
- The `Performance Baseline` workflow runs manually or on the weekly schedule.
- Full Web/API loop covers login through plugin validation, installation,
  task plan, Policy Explain, approval, run, logs, findings, report, and audit.
- Security E2E covers unauthorized targets, high-risk tasks without
  approval, time-window mismatch, plugin exceptions, parser invalid output,
  cancellation, report redaction, and API/Web bypass attempts.
- Deployment and migration E2E includes clean startup, Docker Compose
  config, SQLite schema version `3`, idempotent migration, previous-version
  fixture upgrade, and backup/restore documentation.
- Documentation usability covers README, quickstart, Web usage, protocol,
  plugin development, troubleshooting, and examples.

## Versions

| Component | Version |
| --- | --- |
| CLI | `sentinelflow 0.1.0` |
| Core/workspace crates | `0.1.0` |
| API Service | `0.1.0` |
| Web Console | `0.1.0`, embedded in API Service |
| Protocol | `sentinelflow.io/v1alpha1` |
| SQLite schema | `3` |

## Highlights

- API Service and embedded Web Console for local team trials.
- Replaceable identity-provider interface with development tokens for local use.
- RBAC roles: `viewer`, `operator`, `approver`, and `admin`.
- API-backed Web Console that does not execute tools directly.
- Plugin validation and installation for safe file-based plugins.
- Tool and Task Spec validation for `sentinelflow.io/v1alpha1`.
- Task planning, Policy Explain, high-risk approval, run, status, logs,
  findings/evidence, report generation, and audit listing.
- Command, Docker, HTTP, and File Import adapter contract coverage.
- Python SDK example path for plugin authors without changing Core.
- Safe example plugins and task fixtures for first-run trials.
- Single-node Docker Compose deployment with workspace, plugin, report, and log
  mounts.
- SQLite migration metadata and previous-version upgrade verification.

## Safety Boundary

v1.0-rc keeps SentinelFlow as a management framework:

- Default Policy behavior is deny.
- High-risk mock execution requires approval.
- Tool execution goes through Manifest, Adapter, Parser, Policy, Audit, and
  Normalizer paths.
- Web goes through the API and does not bypass Core execution paths.
- Reports redact sensitive-looking values.
- Safe examples do not perform real scanning or attack behavior.

## Verified Commands

```sh
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
tests/e2e/p5_5_smoke.sh
tests/e2e/p5_5_consistency.sh
tests/e2e/p5_5_full_flow/run.sh
tests/e2e/p5_5_security/run.sh
tests/e2e/p5_5_reliability/run.sh
tests/e2e/p5_5_deployment/run.sh
```

Manual or scheduled release gate:

```sh
tests/performance/run.sh
```

## Deployment

Start with:

- `docs/deployment/local-demo.md`
- `docs/deployment/production-like.md`
- `docs/deployment/upgrade-and-migration.md`
- `docs/v1rc-trial-guide.md`

The active v1.0-rc backend is SQLite. PostgreSQL configuration is documented as
reserved and not active for this release candidate.

## Known Issues

Known Issues are documented in `docs/release/v1_0_rc_known_issues.md`. The most
important constraints are:

- Use only controlled local/private pilots with trusted users.
- Do not expose development static tokens publicly.
- SSE log streaming still uses a query token for browser EventSource support.
- Do not use real secrets, production targets, or unreviewed plugins.
- Keep audit, Policy, Schema validation, Normalizer, and report redaction
  enabled.

## Upgrade Notes

- SQLite schema version `3` is current.
- Re-running migrations is idempotent.
- Previous-version fixtures preserve tools, tasks, runs, findings, audit events,
  and reports after upgrade.
- Back up `state.db`, plugin directories, results, reports, audit, and logs
  before upgrading.

## Release Decision

SentinelFlow v1.0-rc may enter controlled pilot.

It should not be used as a broad production release or as justification to start
P6 features. Broader release readiness requires another gate after resolving or
re-accepting the Known Issues.
