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
- System: `GET /api/system/status`
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

## Web Console Product Experience

The Console is positioned as **SentinelFlow 安全验证工作台**. The default
experience is designed for managers, project managers, delivery and presales
staff, junior security engineers, and non-specialist users.

Normal navigation contains only:

1. 首页
2. 开始检查
3. 检查记录
4. 报告中心
5. 帮助

Administrators additionally receive an 高级功能 entry for plugin management,
raw task configuration, audit logs, and system settings. Plugin names,
`TaskSpec`, Policy internals, raw findings, evidence, and audit JSON are hidden
from the default workflow.

### Three-step P5.6 fixture-only check

An operator starts a check in three visible steps:

1. Enter `example.com` or `example.test` as the local synthetic fixture target.
2. Choose 快速检查. 标准检查 and 深度检查 are P7 placeholders in P5.6.
3. Review the safety summary and confirm the fixture-only run.

The browser then automatically calls the existing API chain:

```text
validate task
→ plan task
→ policy explain
→ run task
→ fetch task result
→ generate P5.6 fixture validation report
→ fetch report and audit-backed status
```

The browser remains an API client. It does not start adapters, execute plugins,
normalize output, evaluate Policy independently, or bypass Core.

### Safe task generation

`web/simple-check.js` provides `buildSimpleCheckTaskSpec()` for the normal-user
workflow.

- Authorization scope is always generated as `fixture:local-only`.
- Allowed targets are limited to `example.com` or `example.test`.
- 快速检查 creates one `subdomain-discovery-plus` step using a local fixture
  file and `passive.subdomain.discovery`.
- The generated task never includes `real:`, `tcp_connect`, `public_resolver`,
  FOFA/Shodan/Censys/crt.sh live providers, `authorized_assessment`, or active
  verification enabled by default.
- 标准检查 and 深度检查 are rejected by the simple builder in P5.6.

### P5.6 API scope protection

Real-target submission is blocked twice:

- Frontend task generation accepts only `example.com` / `example.test` fixture
  targets and asserts the serialized TaskSpec has no P7 active-discovery
  markers.
- `parse_task_request()` rejects `real:` authorization scopes after protocol
  validation. Direct API callers therefore cannot bypass the browser check.

The user-facing error is:

```text
P5.6 API/Web 入口不接受 real: 授权范围。请使用 fixture-only Quick Run。
```

### Result and report semantics

Task execution state and report quality are displayed separately. A completed
task can still produce an unconfirmed or invalid report.

- `valid` + passed quality gate → 可信
- `valid_with_warnings` → 有警告
- `unconfirmed` → 未确认
- failed quality gate or invalid status → 不可信

Candidate assets are never mixed into confirmed assets. A skipped port stage is
shown as “端口检查已跳过：没有可检查的公网 IP”, and a skipped service stage is
shown as “服务识别已跳过：没有确认开放的端口”. Neither state is presented as a
negative finding.

## Verification

P5 adds API contract tests that verify:

- Protected routes reject missing authentication.
- RBAC denies a viewer from plugin installation.
- API Task Plan matches the orchestrator plan for the same Task Spec.
- Plugin validate → install → task run → finding list → report generation →
  report read works through API routes.

Run:

```sh
node --test crates/sentinelflow-api/web/simple-check.test.js
cargo test -p sentinelflow-api
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
