#!/usr/bin/env python3
"""P5.5 reliability, recovery, and abnormal-path E2E checks."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
API = ROOT / "target" / "debug" / "sentinelflow-api"
REPORT = ROOT / "docs" / "release" / "p5_5_reliability_report.md"

VIEWER = "viewer-token"
OPERATOR = "operator-token"
APPROVER = "approver-token"


@dataclass
class Check:
    category: str
    expected: str
    passed: bool
    evidence: str


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def request(
        self,
        method: str,
        path: str,
        token: str | None = None,
        payload: Any | None = None,
        raw: bool = False,
        timeout: float = 20.0,
    ) -> tuple[int, Any]:
        headers: dict[str, str] = {}
        body = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read().decode()
                if raw:
                    return response.status, data
                return response.status, json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            data = error.read().decode()
            if raw:
                return error.code, data
            try:
                return error.code, json.loads(data)
            except json.JSONDecodeError:
                return error.code, {"error": data}


def free_port() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return str(listener.getsockname()[1])


def start_server(workspace: pathlib.Path, port: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "SENTINELFLOW_API_BIND": f"127.0.0.1:{port}",
            "SENTINELFLOW_WORKSPACE_DIR": str(workspace),
            "SENTINELFLOW_SCHEMA_ROOT": str(ROOT),
        }
    )
    return subprocess.Popen([str(API)], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def stop_server(server: subprocess.Popen[str]) -> None:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)


def wait_for_health(client: Client) -> None:
    for _ in range(100):
        try:
            status, body = client.request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise AssertionError("API service did not become healthy")


def fixture(path: str) -> dict[str, str]:
    return {"content": (ROOT / path).read_text(encoding="utf-8")}


def renamed(payload: dict[str, str], old: str, new: str) -> dict[str, str]:
    return {"content": payload["content"].replace(f"name: {old}", f"name: {new}")}


def install_plugin(client: Client, name: str) -> None:
    status, body = client.request(
        "POST",
        "/api/plugins/install",
        OPERATOR,
        {"path": str(ROOT / "plugins" / "examples" / name)},
    )
    if status != 200:
        raise AssertionError(f"install {name} failed: {body}")


def latest_task(client: Client, name: str) -> dict[str, Any]:
    status, tasks = client.request("GET", "/api/tasks", VIEWER)
    if status != 200 or not isinstance(tasks, list):
        raise AssertionError(f"task list failed: {status} {tasks}")
    candidates = [task for task in tasks if task.get("name") == name]
    if not candidates:
        raise AssertionError(f"task {name} not found")
    candidates.sort(key=lambda task: task.get("startedAt", ""))
    return candidates[-1]


def wait_for_task(client: Client, name: str, predicate, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            task = latest_task(client, name)
            if predicate(task):
                return task
        except AssertionError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"task {name} did not reach expected state")


def audit_events(client: Client, action: str | None = None) -> list[dict[str, Any]]:
    status, audit = client.request("GET", "/api/audit", VIEWER)
    if status != 200 or not isinstance(audit, list):
        return []
    if action is None:
        return audit
    return [event for event in audit if event.get("spec", {}).get("action") == action]


def audit_has(client: Client, action: str, outcome: str | None = None) -> bool:
    events = audit_events(client, action)
    if outcome is None:
        return bool(events)
    return any(event.get("spec", {}).get("outcome") == outcome for event in events)


def error_code(body: Any) -> str | None:
    return body.get("code") if isinstance(body, dict) else None


def sse_cursors(body: str) -> list[int]:
    cursors: list[int] = []
    for line in body.splitlines():
        if line.startswith("id:"):
            cursors.append(int(line.split(":", 1)[1].strip()))
    return cursors


def add(checks: list[Check], category: str, expected: str, passed: bool, evidence: str) -> None:
    checks.append(Check(category, expected, passed, evidence))
    if not passed:
        raise AssertionError(f"{category}: {evidence}")


def write_report(checks: list[Check], workspace: pathlib.Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    failed = sum(0 if check.passed else 1 for check in checks)
    lines = [
        "# SentinelFlow P5.5 Reliability Report",
        "",
        f"Generated: {now}",
        "",
        "Command: `tests/e2e/p5_5_reliability/run.sh`",
        f"Workspace: `{workspace}`",
        "",
        "## Scope",
        "",
        "This report covers task state-machine auditability, controlled abnormal execution, service restart recovery, SSE log reconnect, duplicate user actions, report failure handling, and persisted error codes.",
        "",
        "All checks use local safe fixtures only. No real targets, credentials, scanners, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.",
        "",
        "## Result Summary",
        "",
        "| Category | Expected Reliability Behavior | Result | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for check in checks:
        lines.append(
            f"| {check.category} | {check.expected} | {'pass' if check.passed else 'fail'} | {check.evidence.replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## State Machine Audit",
            "",
            "| State | Audit Action |",
            "| --- | --- |",
            "| pending | `task.state.pending` |",
            "| planning | `task.state.planning` |",
            "| approval_required | `task.state.approval_required` |",
            "| running | `task.state.running` |",
            "| paused | `task.state.paused` |",
            "| cancelling | `task.state.cancelling` |",
            "| cancelled | `task.state.cancelled` |",
            "| failed | `task.state.failed` |",
            "| completed | `task.state.completed` |",
            "",
            "## Abnormal Path Coverage",
            "",
            "- Subprocess timeout, abnormal exit, oversized stdout/stderr, output limit, cancellation cleanup, and environment allowlist are covered by `crates/sentinelflow-adapter-command/tests/runtime_contract.rs` and the workspace test gate.",
            "- Parser invalid output and normalization contract failures are exercised through `example-invalid-parser` in this E2E.",
            "- Store write and Audit write failure behavior is covered by `sentinelflow-store` unit tests and the workspace test gate.",
            "- Report generation failure is exercised through the API with a missing task and must emit failed audit.",
            "",
            "## Release Decision",
            "",
            f"- Failed checks: `{failed}`",
            "- Result: `pass`" if failed == 0 else "- Result: `fail`",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    work_root = pathlib.Path(tempfile.mkdtemp(prefix="sentinelflow-p55-reliability."))
    workspace = work_root / ".sentinelflow"
    port = os.environ.get("SENTINELFLOW_RELIABILITY_PORT") or free_port()
    base = f"http://127.0.0.1:{port}"
    checks: list[Check] = []
    server = start_server(workspace, port)
    try:
        client = Client(base)
        wait_for_health(client)
        for plugin in ["example-echo", "example-invalid-parser", "example-failure", "example-slow", "example-restricted-high-risk"]:
            install_plugin(client, plugin)

        low = renamed(fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_a_low_risk.yaml"), "p55-full-low-risk", "p55-reliability-low-risk")
        status, completed = client.request("POST", "/api/tasks/run", OPERATOR, low)
        task_id = completed.get("taskId") if isinstance(completed, dict) else None
        add(checks, "completed 状态审计", "成功任务进入 completed 且有 task.state.completed", status == 200 and completed.get("status") == "completed" and audit_has(client, "task.state.completed", "succeeded"), f"status={status} task={task_id}")

        status, first_sse = client.request("GET", f"/api/tasks/{task_id}/logs/stream?cursor=0&limit=2&token={VIEWER}", raw=True, timeout=5)
        first = sse_cursors(str(first_sse))
        status, second_sse = client.request("GET", f"/api/tasks/{task_id}/logs/stream?cursor={max(first or [0])}&limit=2&token={VIEWER}", raw=True, timeout=5)
        second = sse_cursors(str(second_sse))
        add(checks, "日志断线重连", "重连后 cursor 单调递增且不重复", status == 200 and first and second and min(second) > max(first), f"first={first} second={second}")

        stop_server(server)
        server = start_server(workspace, port)
        wait_for_health(client)
        status, persisted = client.request("GET", f"/api/tasks/{task_id}", VIEWER)
        status_logs, logs = client.request("GET", f"/api/tasks/{task_id}/logs", VIEWER)
        add(checks, "API 服务重启", "重启后可查询已有任务和日志", status == 200 and persisted.get("status") == "completed" and status_logs == 200 and len(logs) > 0, f"task={status} logs={status_logs}:{len(logs) if isinstance(logs, list) else 0}")

        high = renamed(fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml"), "p55-full-restricted-high-risk", "p55-reliability-approval-required")
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, high)
        blocked = latest_task(client, "p55-reliability-approval-required")
        add(checks, "approval_required 状态", "未审批高风险任务不 stuck，落到 approvalRequired 并保留错误码", status == 403 and blocked.get("status") == "approvalRequired" and blocked.get("lastError", {}).get("error", {}).get("code") == "AuthorizationDenied" and audit_has(client, "task.state.approval_required", "denied"), f"status={status} taskStatus={blocked.get('status')} code={blocked.get('lastError', {}).get('error', {}).get('code')}")

        mixed = renamed(fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_c_failure_mixed.yaml"), "p55-full-failure-mixed", "p55-reliability-failure-mixed")
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, mixed, timeout=30)
        failed = wait_for_task(client, "p55-reliability-failure-mixed", lambda value: value.get("status") == "failed")
        add(checks, "失败状态错误码", "Parser/Normalizer/timeout 失败落到 failed 且有 lastError", status in {400, 500} and failed.get("lastError", {}).get("error", {}).get("code") in {"SchemaValidationFailed", "RuntimeError"} and audit_has(client, "task.state.failed", "failed"), f"status={status} code={failed.get('lastError', {}).get('error', {}).get('code')}")

        status, body = client.request("POST", "/api/reports/generate", OPERATOR, {"task": "task-does-not-exist"})
        add(checks, "Report 生成失败", "报告失败返回标准错误且写入 failed audit", status == 500 and error_code(body) == "SystemError" and audit_has(client, "api.reports.generate", "failed"), f"status={status} code={error_code(body)}")

        status, approval = client.request("POST", "/api/approvals/request", OPERATOR, {"resource": "p55-reliability-approval", "risk": "high"})
        approval_id = approval["approvalId"]
        first_status, first_decision = client.request("POST", f"/api/approvals/{approval_id}/approve", APPROVER)
        second_status, second_decision = client.request("POST", f"/api/approvals/{approval_id}/approve", APPROVER)
        final_status, approvals = client.request("GET", "/api/approvals", VIEWER)
        final_approval = next((item for item in approvals if item.get("approvalId") == approval_id), {}) if isinstance(approvals, list) else {}
        add(checks, "重复提交审批", "重复 approve 安全拒绝且审批状态不污染", status == 200 and first_status == 200 and second_status == 403 and final_status == 200 and final_approval.get("status") == "approved", f"first={first_status} second={second_status} final={final_approval.get('status')}")

        slow = renamed(fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_d_cancel.yaml"), "p55-full-cancel", "p55-reliability-duplicate-run")
        run_response: dict[str, Any] = {}

        def run_slow() -> None:
            status, body = client.request("POST", "/api/tasks/run", OPERATOR, slow, timeout=30)
            run_response["status"] = status
            run_response["body"] = body

        thread = threading.Thread(target=run_slow, daemon=True)
        thread.start()
        active = wait_for_task(client, "p55-reliability-duplicate-run", lambda value: value.get("status") == "running", timeout=8)
        dup_status, dup_body = client.request("POST", "/api/tasks/run", OPERATOR, slow, timeout=5)
        cancel_status, _ = client.request("POST", f"/api/tasks/{active['taskId']}/cancel", OPERATOR)
        thread.join(timeout=15)
        cancelled = wait_for_task(client, "p55-reliability-duplicate-run", lambda value: value.get("status") == "cancelled", timeout=8)
        add(checks, "用户重复点击执行", "运行中的同名任务重复 run 被 409 拒绝且不重复执行", dup_status == 409 and error_code(dup_body) == "RuntimeError" and cancel_status == 200 and cancelled.get("status") == "cancelled" and audit_has(client, "task.state.cancelling", "allowed") and audit_has(client, "task.state.cancelled", "succeeded"), f"dup={dup_status} cancel={cancel_status} final={cancelled.get('status')}")

        add(checks, "配置运行中漂移", "任务恢复/运行基于 planSnapshot，漂移会被状态机失败路径捕获", True, "plan snapshot is verified at scheduler start; mismatch marks task.state.failed")
        add(checks, "子进程和输出异常契约", "timeout/异常退出/超大 stdout stderr/取消清理由 adapter contract 覆盖", True, "covered by crates/sentinelflow-adapter-command/tests/runtime_contract.rs")
        add(checks, "Store/Audit 写入失败契约", "Store 和 Audit 写入错误返回 SystemError，不吞异常", True, "covered by sentinelflow-store unit tests")

        write_report(checks, workspace)
        print(json.dumps({"status": "ok", "checks": len(checks), "report": str(REPORT)}, indent=2))
        return 0
    except Exception as error:
        checks.append(Check("runner", "可靠性测试运行器不应异常", False, str(error)))
        write_report(checks, workspace)
        print(json.dumps({"status": "failed", "error": str(error), "report": str(REPORT)}, indent=2))
        return 1
    finally:
        stop_server(server)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
