# SentinelFlow Local Demo Deployment

This guide starts a single-machine SentinelFlow v1.0-rc deployment with the API
Service and Web Console. It uses SQLite at `.sentinelflow/state.db` and safe local
example plugins only.

## Prerequisites

- Docker Engine and Docker Compose v2
- Git checkout of this repository
- No public targets or real credentials

## Start

```sh
docker compose up --build
```

Open:

```text
http://127.0.0.1:8080/console
```

The API and Web Console are served by the same container. The Web Console is only
an API client; it does not execute tools directly.

## Storage

Compose creates named volumes:

| Volume | Container path | Purpose |
| --- | --- | --- |
| `sentinelflow-workspace` | `/data/.sentinelflow` | SQLite DB, tasks, runs, results, audit, approvals |
| `sentinelflow-plugins` | `/data/.sentinelflow/plugins` | Installed plugins |
| `sentinelflow-reports` | `/data/.sentinelflow/reports` | Markdown reports |
| `sentinelflow-logs` | `/data/.sentinelflow/logs` | Operator/service log drop location |

The active database backend for v1.0-rc is SQLite:

```text
/data/.sentinelflow/state.db
```

PostgreSQL is not an active runtime backend in v1.0-rc. Do not set PostgreSQL
secrets expecting the API to use them; see `production-like.md` for the reserved
configuration pattern.

## Safe Demo Flow

Use development-only credentials:

- Login password: `sentinelflow`
- Operator token: `operator-token`
- Viewer token: `viewer-token`

In the Web Console:

1. Log in as operator.
2. Validate plugin path `plugins/examples/example-echo`.
3. Install the plugin.
4. Use the single-step fixture content from `tests/fixtures/task.single-step.yaml`.
5. Plan the task.
6. Run the task.
7. Open logs, findings, report, and audit.

The same flow can be verified with:

```sh
tests/e2e/p5_5_smoke.sh
```

## Local CLI Install

macOS and Linux from a clean checkout:

```sh
cargo build --release -p sentinelflow-cli -p sentinelflow-api
install -m 0755 target/release/sentinelflow /usr/local/bin/sentinelflow
install -m 0755 target/release/sentinelflow-api /usr/local/bin/sentinelflow-api
sentinelflow --workspace .sentinelflow init
sentinelflow --workspace .sentinelflow config show
```

On macOS without permission to `/usr/local/bin`, use `~/.local/bin` and add it
to `PATH`. On Linux, package managers or systemd units may install the same two
binaries under `/usr/local/bin`.

## Safe Defaults

Default policy denies targets outside the Task Spec authorization boundary and
requires explicit approval for high-risk capabilities. The local demo uses only
synthetic fixtures and does not include scanner or exploitation capability.
