# SentinelFlow v1.0-rc Trial Guide

This guide walks a new user through a complete local SentinelFlow trial using
synthetic example plugins only. SentinelFlow is a management framework for
external security validation tools; it is not a scanner, exploit framework, or
attack automation platform.

## Prerequisites

- Rust 1.85 or newer
- Python 3 for the safe example command plugins
- Optional: Docker and Docker Compose for the single-machine deployment path

## Local CLI and API Trial

From a clean clone:

```sh
cargo build --workspace
target/debug/sentinelflow --workspace .sentinelflow init
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow tool run example-echo \
  --input plugins/examples/example-echo/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-one
TASK_ID="$(
  target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/task.single-step.yaml \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["taskId"])'
)"
target/debug/sentinelflow --workspace .sentinelflow report generate --task "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow audit list
```

Then start the API Service:

```sh
SENTINELFLOW_WORKSPACE_DIR=.sentinelflow \
SENTINELFLOW_SCHEMA_ROOT=. \
target/debug/sentinelflow-api
```

Open `http://127.0.0.1:8080/console`.

Use the local development login:

- Username: `operator`
- Password: `sentinelflow`

The Console will receive `operator-token`. For approval actions, use
`approver-token` or login as `approver`.

## Complete Web Flow

Use the Console sections in order:

1. Login and confirm the session.
2. Set plugin path to `plugins/examples/example-echo`.
3. Run plugin validate.
4. Run plugin install.
5. Load tools and inspect `example-echo`.
6. Use the default Task Spec in the editor.
7. Run task validate and task plan.
8. Run Policy Explain and confirm every decision is allowed.
9. Run the task.
10. Copy the returned `taskId` into the Task ID field.
11. Load task status and logs.
12. Connect stream logs; reconnect uses the last cursor.
13. Load findings.
14. Generate a task report.
15. Read the report.
16. Load audit events and confirm API and runtime actions were recorded.

For high-risk approval practice, install
`plugins/examples/example-restricted-high-risk` and use
`tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml`. The
first run should require approval. Request approval as `operator`, approve as
`approver`, add the returned `approvalId` to `spec.policy.approvalRef`, and run
again.

## CLI/API Consistency Check

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow task plan tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace .sentinelflow policy explain tests/fixtures/task.single-step.yaml
```

Compare the CLI plan and Policy Explain output with:

```sh
curl -s \
  -H 'Authorization: Bearer viewer-token' \
  -H 'Content-Type: application/json' \
  --data "{\"content\": $(python3 - <<'PY'
import json
print(json.dumps(open('tests/fixtures/task.single-step.yaml', encoding='utf-8').read()))
PY
)}" \
  http://127.0.0.1:8080/api/tasks/plan
```

Both paths use the same planner and policy evaluation code.

## Docker Compose Trial

```sh
docker compose up --build
```

Then open `http://127.0.0.1:8080/console` and run the Web flow above. The
container stores workspace data in `sentinelflow-workspace` and mounts plugin,
report, and log data through `sentinelflow-plugins`, `sentinelflow-reports`, and
`sentinelflow-logs`.

## E2E Smoke Test

Run the automated local smoke test:

```sh
tests/e2e/p5_5_smoke.sh
```

The script starts the API service on localhost, performs the Web/API workflow via
HTTP, verifies SSE reconnect behavior, generates a report, and checks audit.

## Safety Notes

- Use only synthetic fixtures under `plugins/examples/`, official `example.com`
  fixtures under `plugins/official/`, and fixtures under `tests/fixtures/`.
- Do not enter real credentials, production targets, or operational payloads.
- High or critical risk tasks require approval records before execution.
- Web Console requests go through the API service; it must not execute tools
  directly.
