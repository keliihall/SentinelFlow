# SentinelFlow P5.5 Documentation Usability Report

Generated: 2026-06-15

## Scope

This report covers P5.5-08 documentation usability for a new user starting from a
clean clone. The goal is to complete the safe SentinelFlow trial loop:

1. Build CLI/API binaries.
2. Initialize `.sentinelflow`.
3. Validate and install `example-echo`.
4. Run `tool run`.
5. Run `task run`.
6. Generate a report.
7. Inspect audit events.

No real targets, credentials, scanners, exploits, brute force, stealth,
persistence, bypass, or attack-chain content were added.

## Updated Documentation

| Area | Files |
| --- | --- |
| README and quick start | `README.md`, `README.zh-CN.md`, `docs/v1rc-trial-guide.md` |
| Web usage manual | `docs/api-service-and-web-console.md` |
| Protocol resources | `docs/protocol-v1alpha1.md` |
| Plugin development | `docs/plugin-registry.md`, `plugins/examples/README.md` |
| Troubleshooting | `docs/troubleshooting.md` |
| Complete safe examples | `docs/examples.md` |
| Release traceability | `CHANGELOG.md`, this report |

## Usability Checklist

| Requirement | Status | Evidence |
| --- | --- | --- |
| README explains what SentinelFlow is | pass | `README.md`, `README.zh-CN.md` |
| README explains what SentinelFlow is not | pass | Scanner/exploit/brute-force/bypass exclusions documented |
| Core architecture documented | pass | README architecture diagram and crate/path conventions |
| Quick start covers install/init/plugin/tool/task/report/audit | pass | README and Trial Guide command blocks |
| Web manual covers full user workflow | pass | Login, plugin, tools, Task Spec, plan, approval, run, logs, findings, report, audit |
| Protocol docs cover key resources | pass | Tool Manifest, Task Spec, Finding, Evidence, StandardError, Audit Event, Policy |
| Plugin docs cover structure, Manifest, Runner, Parser, local tests, safety | pass | `docs/plugin-registry.md` |
| Troubleshooting covers requested failures | pass | Plugin validation, Policy, Parser, timeout, report, Web logs |
| Complete examples are safe | pass | `example-echo`, `example-file-import`, restricted-risk mock, single-step, approval-required, partial-failure |
| P6 promises avoided | pass | Docs describe PostgreSQL/P6-like features as not active or out of scope |

## Verified Commands

Core quick start:

```sh
cargo build --workspace
target/debug/sentinelflow --workspace <tmp>/.sentinelflow init
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace <tmp>/.sentinelflow tool list
target/debug/sentinelflow --workspace <tmp>/.sentinelflow tool run example-echo --input plugins/examples/example-echo/examples/input.json --authorization-scope fixture:local-only --target fixture-one
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task validate tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task plan tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow policy explain tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task run tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow report generate --task <TASK_ID>
target/debug/sentinelflow --workspace <tmp>/.sentinelflow audit list
```

Safe examples:

```sh
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin validate plugins/examples/example-file-import
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin install plugins/examples/example-file-import
target/debug/sentinelflow --workspace <tmp>/.sentinelflow tool run example-file-import --input plugins/examples/example-file-import/examples/input.json --authorization-scope fixture:local-only --target fixture-import
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin validate plugins/examples/example-restricted-high-risk
target/debug/sentinelflow --workspace <tmp>/.sentinelflow plugin install plugins/examples/example-restricted-high-risk
target/debug/sentinelflow --workspace <tmp>/.sentinelflow policy explain tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow approval request --resource p55-full-restricted-high-risk --risk high
target/debug/sentinelflow --workspace <tmp>/.sentinelflow approval approve <APPROVAL_ID>
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task run /tmp/sentinelflow-approved-task-docs.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task validate tests/fixtures/p5_5/task.partial-failure.yaml
target/debug/sentinelflow --workspace <tmp>/.sentinelflow task plan tests/fixtures/p5_5/task.partial-failure.yaml
```

Web/API startup:

```sh
SENTINELFLOW_WORKSPACE_DIR=/tmp/sf-docs-web/.sentinelflow \
SENTINELFLOW_SCHEMA_ROOT=. \
SENTINELFLOW_API_BIND=127.0.0.1:18080 \
target/debug/sentinelflow-api
curl -fsS http://127.0.0.1:18080/health
curl -fsS http://127.0.0.1:18080/console
```

Protocol and Schema validation:

```sh
cargo test -p sentinelflow-schema
target/debug/sentinelflow tool validate tests/fixtures/v1alpha1/valid-tool-manifest.json
target/debug/sentinelflow task validate tests/fixtures/v1alpha1/valid-task-spec.json
```

Workspace gates:

```sh
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Notes

- `tool validate` currently validates standalone JSON Manifest fixtures.
  Repository plugin YAML Manifests are validated through `plugin validate`.
- High-risk and partial-failure examples intentionally return controlled
  non-zero outcomes until approval or failure policy handling is demonstrated.
- Web Console SSE still uses a development query token path documented elsewhere
  as a release hardening action; this task did not implement P6 or unrelated auth
  redesign.

## Result

P5.5-08 documentation usability acceptance: pass.
