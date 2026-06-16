# SentinelFlow v1.0-rc Release Gate

Generated: 2026-06-15T05:13:31Z
Updated: 2026-06-16T03:20:51Z

## Conclusion

SentinelFlow v1.0-rc is releasable for a controlled single-node pilot.

The final candidate commit must have a successful GitHub Actions `CI` run. This
report records the gate set and local evidence; the authoritative automated
status is the latest `CI` run for the target commit on `main`.

This is not a broad production or public security-testing release. The pilot
scope is limited to trusted operators, local or private deployments, safe
example plugins, approved high-risk mock tasks, and synthetic validation data.
The release gate found no Release Blocker for that controlled pilot scope.

## Release Scope

SentinelFlow is a network security validation tool management framework. It is
not a scanner, exploit platform, brute-force system, stealth probing system,
authentication bypass tool, persistence framework, or attack-chain automation
platform.

The v1.0-rc candidate includes:

- Rust CLI/Core/API/Web workspace version `0.1.0`.
- Protocol version `sentinelflow.io/v1alpha1`.
- SQLite schema migration version `3`.
- API-backed Web Console.
- Safe adapters and example plugins only.
- Default-deny Policy, high-risk approval, Audit Events, normalization, and
  report generation.
- Single-node Docker Compose deployment for local pilots.

## Version Check

| Component | Version | Source | Result |
| --- | --- | --- | --- |
| CLI binary | `sentinelflow 0.1.0` | `target/debug/sentinelflow --version` | pass |
| Core/workspace crates | `0.1.0` | workspace `Cargo.toml` and `cargo metadata` | pass |
| API Service | `0.1.0` | `sentinelflow-api` crate and OpenAPI info version | pass |
| Web Console | `0.1.0` | embedded in `sentinelflow-api` package | pass |
| Protocol | `sentinelflow.io/v1alpha1` | schemas and `sentinelflow-schema` constants | pass |
| DB migration | `3` | `sentinelflow-store` schema metadata and deployment E2E | pass |
| Rust baseline | `1.85` | workspace `rust-version` | pass |

Note: the Web Console does not yet expose an independent UI version endpoint.
For v1.0-rc it is versioned with the API crate that serves it.

## Gate Checklist

| Gate | Evidence | Result |
| --- | --- | --- |
| Build passes | `cargo build --workspace` | pass |
| Format passes | `cargo fmt --all -- --check` | pass |
| Clippy passes | `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| Unit and contract tests pass | `cargo test --workspace` | pass |
| Integration/E2E smoke | `tests/e2e/p5_5_smoke.sh` | pass |
| CLI/API/Web consistency | `tests/e2e/p5_5_consistency.sh` and `docs/release/p5_5_consistency_report.md` | pass |
| Full business loop | `tests/e2e/p5_5_full_flow/run.sh` and `docs/release/p5_5_e2e_report.md` | pass |
| Security hardening | `tests/e2e/p5_5_security/run.sh` and `docs/release/p5_5_security_hardening_report.md` | pass |
| Reliability and failure handling | `tests/e2e/p5_5_reliability/run.sh` and `docs/release/p5_5_reliability_report.md` | pass |
| Deployment and migration | `tests/e2e/p5_5_deployment/run.sh` and `docs/release/p5_5_deployment_report.md` | pass |
| Docker Compose config | `docker compose config` | pass |
| Performance baseline | `tests/performance/run.sh` and `docs/release/p5_5_performance_baseline_metrics.json` | pass |
| Documentation usability | `docs/release/p5_5_docs_usability_report.md` | pass |
| Example plugin validation | `target/debug/sentinelflow plugin validate plugins/examples/example-echo` | pass |
| Protocol fixture validation | `tool validate` and `task validate` over `tests/fixtures/v1alpha1` | pass |
| CHANGELOG | `CHANGELOG.md` updated for v1.0-rc gate artifacts | pass |
| Release notes | `docs/release/v1_0_rc_release_notes.md` | pass |
| Known issues | `docs/release/v1_0_rc_known_issues.md` | pass |

## Command Evidence

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
tests/performance/run.sh
docker compose config
target/debug/sentinelflow tool validate tests/fixtures/v1alpha1/valid-tool-manifest.json
target/debug/sentinelflow task validate tests/fixtures/v1alpha1/valid-task-spec.json
target/debug/sentinelflow plugin validate plugins/examples/example-echo
```

The default GitHub Actions `CI` workflow runs the fmt/build/clippy/test and
P5.5 E2E commands on push and pull request. The performance baseline is
intentionally run by the separate manual or scheduled `Performance Baseline`
workflow so ordinary PR CI does not become capacity-test bound.

## Minimum Standard Review

| Minimum Standard | Evidence | Result |
| --- | --- | --- |
| CLI/API/Web full loop is consistent | Six shared Task Spec fixtures compare plan, policy, run, findings, report, and audit with zero differences. | pass |
| Default configuration remains safe | Policy defaults deny, unauthorized targets are rejected, high-risk tasks require approval. | pass |
| High-risk approval works | Full E2E scenario requests approval, approves with an approver, and executes only with `approvalRef`. | pass |
| Critical path Audit Events exist | Login, plugin validate/install, task plan/run/cancel, approvals, policy denial, normalization, report generation covered. | pass |
| Deployment docs exist and smoke passes | Compose config parses; clean API/Web startup and example-echo flow pass. | pass |
| Migration and upgrade are verified | Previous-version fixture upgrades to schema version `3` and preserves tools/tasks/runs/findings/audit/reports. | pass |
| Examples are safe and runnable | `example-echo`, file import, restricted-risk mock, and task examples are documented and validated. | pass |
| No blocking data-loss issue known | Upgrade preservation and idempotent migration tests pass. | pass |
| No known high-risk security issue for controlled pilot scope | Remaining security issues are accepted only with local trusted pilot constraints. | pass with constraints |

## Performance Snapshot

Latest raw metrics: `docs/release/p5_5_performance_baseline_metrics.json`

| Metric | Observed |
| --- | ---: |
| API latency P50 / P95 / P99 | 35.50 ms / 153.45 ms / 400.30 ms |
| Task plan P50 / P95 / P99 | 55.73 ms / 165.31 ms / 219.62 ms |
| Task run scheduling P50 / P95 / P99 | 946.72 ms / 1036.79 ms / 1036.79 ms |
| Bulk Finding task duration | 5555.36 ms for 128 additional targets |
| Log push P50 / P95 / P99 | 27.71 ms / 61.11 ms / 61.11 ms |
| Finding query latency | 12.59 ms for 136 findings |
| Finding write throughput | 20.63 findings/s |
| Audit write throughput | 195.56 requested audit writes/s |
| Report generation P50 / P95 / P99 | 25.25 ms / 29.26 ms / 29.26 ms |
| API RSS growth | 7.6 MiB to 29.5 MiB |
| Workspace growth | 73,050 bytes to 1,775,503 bytes |
| SQLite database size | 1,048,576 bytes |

## Issue Classification Summary

| Classification | Count | Release Decision |
| --- | ---: | --- |
| Release Blocker | 0 | Does not block controlled v1.0-rc pilot. |
| Known Issue | 8 | Accepted for controlled pilot with documented mitigations. |
| Deferred | 6 | Not required for v1.0-rc pilot; must not be treated as P6 readiness. |

See `docs/release/v1_0_rc_known_issues.md` for the full register.

## Final Decision

The release gate is passed for v1.0-rc controlled pilot entry.

Do not use this conclusion to start P6 work automatically. Before broader pilot
or public release, close or re-review the accepted Known Issues, especially API
business-boundary cleanup, SSE stream authentication, production authentication
guardrails, OpenAPI completeness, and container runtime hardening.
