# SentinelFlow P5 API Service and Web Console

## Scope

P5 introduces a team-facing API service and a minimal Web Console. The Console is
an API client only: it does not start tools, does not load plugins, and does not
evaluate Policy in browser code.

The API service is implemented in `crates/sentinelflow-api` and reuses existing
SentinelFlow crates for protocol validation, DAG planning, policy decisions,
plugin validation, task execution, persistence, reports, and audit.

## Running Locally

```sh
cargo run -p sentinelflow-api
```

Defaults:

- Bind address: `127.0.0.1:8080`
- Workspace: `.sentinelflow`
- Schema root: `.`

Environment overrides:

- `SENTINELFLOW_API_BIND`
- `SENTINELFLOW_WORKSPACE_DIR`
- `SENTINELFLOW_SCHEMA_ROOT`

Open the Console at `http://127.0.0.1:8080/console`.

## Authentication and Sessions

The API has a replaceable identity provider boundary:

- `IdentityProvider::authenticate_token`
- `IdentityProvider::issue_session`

The current local provider is deliberately small and replaceable. Development
tokens are:

- `viewer-token`
- `operator-token`
- `approver-token`
- `admin-token`

Login uses password `sentinelflow` for local development. Production identity
providers must replace this provider rather than changing route handlers.

## RBAC

Minimal roles:

- `viewer`: read tools, tasks, runs, findings, reports, approvals, audit, and
  Policy Explain.
- `operator`: viewer plus plugin validation/install/test, task run/cancel, report
  generation, and approval request.
- `approver`: viewer plus approval approve/reject/expire.
- `admin`: all permissions.

Mutating endpoints require authentication, authorization, and audit events.

## Resource Endpoints

The service exposes:

- Tools: `GET /api/tools`, `GET /api/tools/{name}`
- Plugins: `GET /api/plugins`, `POST /api/plugins/validate`,
  `POST /api/plugins/install`, `POST /api/plugins/test`
- Tasks: `GET /api/tasks`, `POST /api/tasks/validate`,
  `POST /api/tasks/plan`, `POST /api/tasks/run`, `GET /api/tasks/{taskId}`,
  `POST /api/tasks/{taskId}/cancel`
- Runs: `GET /api/runs`, `GET /api/runs/{runId}`
- Findings: `GET /api/findings`
- Reports: `GET /api/reports`, `POST /api/reports/generate`,
  `GET /api/reports/{reportId}`
- Audit: `GET /api/audit`
- Approvals: `GET /api/approvals`, `POST /api/approvals/request`,
  `POST /api/approvals/{approvalId}/approve`,
  `POST /api/approvals/{approvalId}/reject`,
  `POST /api/approvals/{approvalId}/expire`
- Policy Explain: `POST /api/policy/explain`

OpenAPI JSON is available at `GET /openapi.json`.

List endpoints for tasks, runs, findings, reports, audit events, approvals, and
task logs accept `limit` and `offset` query parameters. Defaults are bounded:
general lists return up to 100 items and are capped at 500; task log lists return
up to 200 events and are capped at 1,000. This keeps Web/API behavior stable in
large workspaces.

Report generation rejects a run or task report above the v1.0-rc default limit
of 5,000 findings instead of loading an unbounded report into the API process.

## Real-Time Logs

Task logs are streamed with SSE:

```text
GET /api/tasks/{taskId}/logs/stream?cursor=0&limit=200&token=viewer-token
```

Each event includes a monotonically increasing cursor. Clients reconnect with the
last cursor to continue from the next audit event. The standard JSON log list is
also available at `GET /api/tasks/{taskId}/logs`.

The optional `limit` query parameter bounds emitted events. Omitting it defaults
to 200 events; the API caps one stream response at 1,000 events.

## Web Console Pages

The Console is intentionally workflow-first, not a display dashboard. Use the
sections in this order for a complete safe trial:

1. Login and workspace.
   - Select `operator`, keep password `sentinelflow`, and click Login.
   - The token field should become `operator-token`.
   - Click Show Session to verify the authenticated role.
2. Plugin management.
   - Set Plugin Path to `plugins/examples/example-echo`.
   - Click Validate Plugin.
   - Click Install Plugin.
   - Click Test Plugin when you want the plugin fixture tested through the normal
     temporary workspace path.
3. Tool management.
   - Click Load Tools.
   - Confirm `example-echo` appears.
   - Enter `example-echo` in Tool Name and click Tool Detail to inspect the
     Manifest, runtime adapter, parser, Schema paths, and capabilities.
4. Task Spec editing.
   - Use the default low-risk Task Spec or paste a safe fixture from
     `tests/fixtures/task.single-step.yaml`.
   - Do not enter real targets or credentials.
5. Task plan.
   - Click Validate Task.
   - Click Plan Task.
   - Review the DAG order and step names.
6. Policy Explain and approval.
   - Click Policy Explain before running.
   - Low-risk `example-echo` decisions should be allowed.
   - For a high-risk approval trial, install
     `plugins/examples/example-restricted-high-risk`, submit
     `tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml`,
     request approval as `operator`, then login as `approver` or use
     `approver-token` to approve. Add the returned approval ID as
     `spec.policy.approvalRef` before rerunning.
7. Task execution.
   - Click Run Task.
   - Copy the returned `taskId` into the Task ID field.
   - Click Task Status to verify `completed`, `approvalRequired`, `failed`, or
     another controlled state.
8. Logs.
   - Click Task Logs for bounded JSON log history.
   - Click Stream Logs to open the SSE stream. Reconnect resumes from the last
     cursor.
9. Finding and Evidence.
   - Click Findings.
   - Findings include stable `fingerprint`, `crossToolFingerprint`, severity,
     summary, and structured Evidence.
10. Reports.
    - Paste the `taskId` into Report Task ID or Run ID.
    - Click Generate Task Report.
    - Click Read Report to view Markdown.
11. Audit.
    - Click Audit Events.
    - Confirm plugin validation/install, task run, normalization, report, and
      policy or approval decisions appear as Audit Events.
12. System and protocol center.
    - Click Health and OpenAPI to verify service status and route metadata.

All buttons call `/api/...` routes. Browser code never invokes adapters or
duplicates Policy checks.

## Verification

P5 adds API contract tests that verify:

- Protected routes reject missing authentication.
- RBAC denies a viewer from plugin installation.
- API Task Plan matches the orchestrator plan for the same Task Spec.
- Plugin validate → install → task run → finding list → report generation →
  report read works through API routes.

Run:

```sh
cargo test -p sentinelflow-api
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
