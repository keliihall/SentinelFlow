# SentinelFlow

[中文说明](README.zh-CN.md)

SentinelFlow is a management framework for external security validation tools. It
standardizes how tools are registered, validated, executed, normalized, audited,
governed by policy, and reported.

SentinelFlow is not a scanner, exploit framework, brute-force tool, offensive
automation platform, credential bypass tool, persistence framework, stealth
probing engine, or attack-chain system. This repository contains safe framework
capabilities, protocol contracts, adapters, local examples, and tests only.

## Current Version

The repository is preparing a `v1.0-rc` candidate for controlled local and small
team trials.

Implemented capabilities:

- `sentinelflow` CLI
- `sentinelflow.io/v1alpha1` protocol and JSON Schemas
- Tool Manifest validation, plugin discovery, plugin install, and registry query
- Command, Docker, HTTP, and File Import adapters
- DAG task planning and task execution
- Default-deny Policy, Policy Explain, and approval workflow
- Audit Event, Run, Result, Finding/Evidence, and Markdown report persistence
- API Service and embedded Web Console
- Python SDK example path
- Single-machine Docker Compose deployment
- P5.5 consistency, security, reliability, deployment, and performance gates

Supported deployment boundary:

- `v1.0-rc` supports single-node local or small-team pilots.
- SQLite is the only active runtime store backend.
- PostgreSQL configuration examples are reserved for future work and are not an
  implemented backend in this release candidate.
- Built-in development identities are for local trials only. Production-like
  pilots must put SentinelFlow behind real authentication or a trusted reverse
  proxy.

Not included in `v1.0-rc`:

- Plugin marketplace
- Distributed workers
- AI automatic analysis
- Advanced team spaces
- Real vulnerability scanning or exploitation
- Brute force, credential attacks, persistence, stealth, bypass, or attack chains

## Core Architecture

```text
CLI / API / Web Console
        |
        v
Task Spec -> Planner -> Policy -> Adapter -> Parser -> Normalizer -> Store
                                  |                         |
                                  v                         v
                               Audit                    Report
```

Stable identifiers:

| Item | Value |
| --- | --- |
| Product name | `SentinelFlow` |
| CLI binary | `sentinelflow` |
| Workspace directory | `.sentinelflow/` |
| API group | `sentinelflow.io` |
| Protocol version | `sentinelflow.io/v1alpha1` |
| Environment prefix | `SENTINELFLOW_` |

Crates live under `crates/sentinelflow-*`. Schemas live under
`schemas/v1alpha1/`. Safe example plugins live under `plugins/examples/`.

## Quick Start: CLI

Prerequisites:

- Rust 1.85 or newer
- Python 3 for the safe example Command plugins

Build the local binaries:

```sh
cargo build --workspace
```

Initialize a workspace and install the safe `example-echo` plugin:

```sh
target/debug/sentinelflow --workspace .sentinelflow init
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow tool list
```

Run the tool directly through Policy, Adapter, Parser, Normalizer, Store, and
Audit:

```sh
target/debug/sentinelflow --workspace .sentinelflow tool run example-echo \
  --input plugins/examples/example-echo/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-one
```

Validate, plan, and run a single-step Task Spec:

```sh
target/debug/sentinelflow --workspace .sentinelflow task validate tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace .sentinelflow task plan tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace .sentinelflow policy explain tests/fixtures/task.single-step.yaml

TASK_ID="$(
  target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/task.single-step.yaml \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["taskId"])'
)"
target/debug/sentinelflow --workspace .sentinelflow task status "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow task logs "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow report generate --task "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow audit list
```

Generated artifacts are written under `.sentinelflow/runs`,
`.sentinelflow/results`, `.sentinelflow/reports`, `.sentinelflow/audit`, and
`.sentinelflow/state.db`.

## Quick Start: Web Console

Start the API Service:

```sh
SENTINELFLOW_WORKSPACE_DIR=.sentinelflow \
SENTINELFLOW_SCHEMA_ROOT=. \
target/debug/sentinelflow-api
```

Open `http://127.0.0.1:8080/console`.

Development login:

| Role | Username | Password | Token |
| --- | --- | --- | --- |
| Viewer | `viewer` | `sentinelflow` | `viewer-token` |
| Operator | `operator` | `sentinelflow` | `operator-token` |
| Approver | `approver` | `sentinelflow` | `approver-token` |
| Admin | `admin` | `sentinelflow` | `admin-token` |

Use the Console sections in order: login, validate/install plugin, inspect tool,
edit Task Spec, plan, Policy Explain, run, logs, Findings/Evidence, report, and
audit. Full steps are in [API Service and Web Console](docs/api-service-and-web-console.md).

## Safety Boundary

SentinelFlow defaults to deny:

- Tools must enter through Manifest + Adapter + Parser.
- Adapters must not bypass Policy, Audit, Parser, Normalizer, or Store.
- Web Console is an API client only and must not execute tools directly.
- API must reuse the existing SentinelFlow orchestration path.
- All outputs are schema-validated and normalized before persistence.
- Key actions and decisions write Audit Events.
- Untrusted plugins are not loaded as in-process dynamic libraries.
- Examples use local synthetic fixtures only.

Do not put real targets, real credentials, production secrets, or offensive
payloads in plugins, fixtures, docs, or tests.

## Safe Examples

- `plugins/examples/example-echo`: local low-risk echo.
- `plugins/examples/example-file-import`: bounded JSON/JSONL/CSV import.
- `plugins/examples/example-restricted-high-risk`: local echo marked high risk to
  test approval.
- `tests/fixtures/task.single-step.yaml`: successful single-step task.
- `tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml`:
  approval-required task.
- `tests/fixtures/p5_5/task.partial-failure.yaml`: partial failure DAG.

See [Safe Examples](docs/examples.md) for copyable commands.

## Documentation

- [v1.0-rc Trial Guide](docs/v1rc-trial-guide.md)
- [CLI Guide](docs/cli.md)
- [API Service and Web Console](docs/api-service-and-web-console.md)
- [Protocol v1alpha1](docs/protocol-v1alpha1.md)
- [Plugin Development and Registry](docs/plugin-registry.md)
- [Safe Examples](docs/examples.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Boundary](docs/security-boundary.md)
- [Results, Audit, and Reports](docs/results-audit-reporting.md)
- [Deployment: Local Demo](docs/deployment/local-demo.md)
- [Deployment: Production-like](docs/deployment/production-like.md)
- [Release Notes](docs/release-v1.0-rc.md)
- [Acceptance Report](docs/v1.0-rc-acceptance-report.md)
- [Performance Baseline](docs/release/p5_5_performance_baseline.md)

## Release Gates

The default GitHub Actions `CI` workflow runs the required pre-release gates
below except the performance baseline. The performance baseline runs in the
separate `Performance Baseline` workflow by `workflow_dispatch` or the weekly
schedule.

Required CI gates:

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

The deployment gate uses loopback ports and `docker compose config`; CI runners
must provide Python 3, Docker, and Docker Compose. The E2E gates only use local
synthetic fixtures and do not contact real targets.

## Current Limits And Next Stage

Known `v1.0-rc` limits:

- Single-node operation only; no distributed Worker.
- SQLite only; PostgreSQL is not active.
- Development authentication is not production authentication.
- Web Console is an API-backed workflow console, not a full dashboard.
- SSE log streaming still uses the documented local-pilot token flow.
- Example plugins are safe local fixtures, not real scanners.

P6 planning areas, not implemented in this release:

- Plugin ecosystem and marketplace.
- Team collaboration and stronger identity integration.
- Distributed Worker execution.
- AI-assisted analysis over already-normalized safe findings.
