#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-p55.XXXXXX")"
PORT="${SENTINELFLOW_E2E_PORT:-18080}"
LOG="$WORKDIR/api.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

cd "$ROOT"
cargo build -p sentinelflow-api -p sentinelflow-cli

SENTINELFLOW_API_BIND="127.0.0.1:${PORT}" \
SENTINELFLOW_WORKSPACE_DIR="$WORKDIR/.sentinelflow" \
SENTINELFLOW_SCHEMA_ROOT="$ROOT" \
  target/debug/sentinelflow-api >"$LOG" 2>&1 &
SERVER_PID="$!"

python3 - "$ROOT" "$PORT" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

root = sys.argv[1]
port = sys.argv[2]
base = f"http://127.0.0.1:{port}"

def request(method, path, token=None, payload=None, raw=False):
    headers = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        data = response.read()
        if raw:
            return response.status, data.decode()
        if not data:
            return response.status, None
        return response.status, json.loads(data)

for _ in range(100):
    try:
        status, health = request("GET", "/health")
        if status == 200 and health["status"] == "ok":
            break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("API service did not become healthy")

status, console = request("GET", "/console", raw=True)
assert status == 200 and "SentinelFlow 安全验证工作台" in console, console[:500]
assert "任务状态与报告可信度分别展示" in console, "missing product result semantics"

status, simple_check = request("GET", "/console/simple-check.js", raw=True)
assert status == 200 and "buildSimpleCheckTaskSpec" in simple_check, simple_check[:500]
assert "fixture:local-only" in simple_check and "example.com" in simple_check and "example.test" in simple_check
assert "P5_6_FORBIDDEN_MARKERS" in simple_check and "assertP56FixtureOnly" in simple_check

status, session = request(
    "POST",
    "/api/session/login",
    payload={"username": "operator", "password": "sentinelflow"},
)
assert status == 200, session
operator = session["token"]

plugin = f"{root}/plugins/examples/example-echo"
for endpoint in ["/api/plugins/validate", "/api/plugins/install"]:
    status, body = request("POST", endpoint, operator, {"path": plugin})
    assert status == 200, body

status, tools = request("GET", "/api/tools", "viewer-token")
assert status == 200 and any(tool["name"] == "example-echo" for tool in tools), tools

with open(f"{root}/tests/fixtures/task.single-step.yaml", encoding="utf-8") as handle:
    task_content = handle.read()

status, plan = request("POST", "/api/tasks/plan", "viewer-token", {"content": task_content})
assert status == 200 and plan["executionOrder"] == ["echo"], plan

status, policy = request("POST", "/api/policy/explain", "viewer-token", {"content": task_content})
assert status == 200 and all(item["decision"]["allowed"] for item in policy), policy

status, task = request("POST", "/api/tasks/run", operator, {"content": task_content})
assert status == 200 and task["status"] == "completed", task
task_id = task["taskId"]

status, logs = request("GET", f"/api/tasks/{task_id}/logs", "viewer-token")
assert status == 200 and any(event["spec"]["action"] == "result.normalized" for event in logs), logs

status, sse = request(
    "GET",
    f"/api/tasks/{task_id}/logs/stream?cursor=1&limit=1&token=viewer-token",
    raw=True,
)
assert status == 200 and "event: audit" in sse and '"cursor":2' in sse, sse

status, findings = request("GET", "/api/findings", "viewer-token")
assert status == 200 and len(findings) >= 1, findings

status, report = request("POST", "/api/reports/generate", operator, {"task": task_id})
assert status == 200 and report["reportId"] == task_id, report

status, markdown = request("GET", f"/api/reports/{task_id}", "viewer-token", raw=True)
assert status == 200 and "SentinelFlow Task Report" in markdown, markdown

status, audit = request("GET", "/api/audit", "viewer-token")
assert status == 200 and any(event["spec"]["action"] == "api.reports.generate" for event in audit), audit

print(json.dumps({"status": "ok", "taskId": task_id, "findings": len(findings)}, indent=2))
PY
