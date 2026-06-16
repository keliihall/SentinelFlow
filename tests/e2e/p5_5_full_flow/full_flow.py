#!/usr/bin/env python3
"""P5.5 full end-to-end user-flow verification."""

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
API = ROOT / "target" / "debug" / "sentinelflow-api"
FIXTURES = ROOT / "tests" / "e2e" / "p5_5_full_flow" / "fixtures"
REPORT = ROOT / "docs" / "release" / "p5_5_e2e_report.md"

OPERATOR = "operator-token"
VIEWER = "viewer-token"
APPROVER = "approver-token"


@dataclass
class StepResult:
    scenario: str
    step: str
    passed: bool
    detail: str


@dataclass
class ScenarioResult:
    name: str
    description: str
    steps: list[StepResult] = field(default_factory=list)

    def check(self, step: str, condition: bool, detail: str) -> None:
        self.steps.append(StepResult(self.name, step, condition, detail))
        if not condition:
            raise AssertionError(f"{self.name}::{step}: {detail}")

    @property
    def passed(self) -> bool:
        return all(step.passed for step in self.steps)


class HttpClient:
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
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers=headers,
            method=method,
        )
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


def task_content(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def task_payload(name: str) -> dict[str, str]:
    return {"content": task_content(name)}


def api_error_code(body: Any) -> str | None:
    return body.get("code") if isinstance(body, dict) else None


def wait_for_health(client: HttpClient) -> dict[str, Any]:
    for _ in range(100):
        try:
            status, body = client.request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return body
        except Exception:
            pass
        time.sleep(0.1)
    raise AssertionError("API service did not become healthy")


def free_port() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return str(listener.getsockname()[1])


def install_plugin(client: HttpClient, name: str, validate_first: bool = False) -> None:
    plugin_path = str(ROOT / "plugins" / "examples" / name)
    if validate_first:
        status, body = client.request(
            "POST",
            "/api/plugins/validate",
            OPERATOR,
            {"path": plugin_path},
        )
        if status != 200:
            raise AssertionError(f"plugin validate failed for {name}: {body}")
    status, body = client.request(
        "POST",
        "/api/plugins/install",
        OPERATOR,
        {"path": plugin_path},
    )
    if status != 200:
        raise AssertionError(f"plugin install failed for {name}: {body}")


def install_many(client: HttpClient, names: list[str]) -> None:
    for name in names:
        install_plugin(client, name)


def latest_task_by_name(client: HttpClient, name: str) -> dict[str, Any] | None:
    status, tasks = client.request("GET", "/api/tasks", VIEWER)
    if status != 200 or not isinstance(tasks, list):
        return None
    candidates = [task for task in tasks if task.get("name") == name]
    if not candidates:
        return None
    candidates.sort(key=lambda task: task.get("startedAt", ""))
    return candidates[-1]


def wait_for_task(client: HttpClient, name: str, predicate, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = latest_task_by_name(client, name)
        if task is not None and predicate(task):
            return task
        time.sleep(0.05)
    raise AssertionError(f"task {name} did not reach expected state")


def audit_actions(client: HttpClient) -> list[str]:
    status, audit = client.request("GET", "/api/audit", VIEWER)
    if status != 200 or not isinstance(audit, list):
        return []
    return [event.get("spec", {}).get("action") for event in audit if event.get("spec")]


def generate_and_read_report(client: HttpClient, task_id: str) -> str:
    status, body = client.request(
        "POST",
        "/api/reports/generate",
        OPERATOR,
        {"task": task_id},
    )
    if status != 200:
        raise AssertionError(f"report generation failed for {task_id}: {body}")
    status, markdown = client.request("GET", f"/api/reports/{task_id}", VIEWER, raw=True)
    if status != 200:
        raise AssertionError(f"report read failed for {task_id}: {markdown}")
    return str(markdown)


def scenario_a(client: HttpClient) -> ScenarioResult:
    result = ScenarioResult("A", "低风险工具执行闭环")
    status, console = client.request("GET", "/console", raw=True)
    result.check("open Web Console", status == 200 and "SentinelFlow Console" in console, "console page is served")
    status, session = client.request(
        "POST",
        "/api/session/login",
        payload={"username": "operator", "password": "sentinelflow"},
    )
    result.check("login Web", status == 200 and session["token"] == OPERATOR, "operator login issues development token")

    status, health = client.request("GET", "/health")
    result.check("initialize system", status == 200 and health["status"] == "ok", "health endpoint is ready")

    plugin_path = str(ROOT / "plugins" / "examples" / "example-echo")
    status, validation = client.request("POST", "/api/plugins/validate", OPERATOR, {"path": plugin_path})
    result.check("validate plugin", status == 200 and all(check["passed"] for check in validation["checks"]), "example-echo validates")
    status, install = client.request("POST", "/api/plugins/install", OPERATOR, {"path": plugin_path})
    result.check("install plugin", status == 200 and "Installed" in install["outcome"], "example-echo installed")
    status, tools = client.request("GET", "/api/tools", VIEWER)
    result.check("view tool list", status == 200 and any(tool["name"] == "example-echo" for tool in tools), "tool list includes example-echo")

    payload = task_payload("scenario_a_low_risk.yaml")
    status, task_validation = client.request("POST", "/api/tasks/validate", OPERATOR, payload)
    result.check("create and validate low-risk Task Spec", status == 200 and task_validation["valid"], "Task Spec validates")
    status, plan = client.request("POST", "/api/tasks/plan", VIEWER, payload)
    result.check("task plan", status == 200 and plan["executionOrder"] == ["echo"], "plan is deterministic")
    status, run_body = client.request("POST", "/api/tasks/run", OPERATOR, payload)
    result.check("execute task", status == 200 and run_body["status"] == "completed", "low-risk task completed")
    task_id = run_body["taskId"]

    status, sse = client.request(
        "GET",
        f"/api/tasks/{task_id}/logs/stream?cursor=0&limit=1&token={VIEWER}",
        raw=True,
        timeout=5,
    )
    result.check("view realtime logs", status == 200 and "event: audit" in sse, "SSE stream emits audit event")
    status, findings = client.request("GET", "/api/findings", VIEWER)
    result.check("view Finding", status == 200 and len(findings) >= 1 and findings[0].get("fingerprint"), "finding includes fingerprint")
    markdown = generate_and_read_report(client, task_id)
    result.check("generate report", "SentinelFlow Task Report" in markdown and "- Findings: 1" in markdown, "report includes finding summary")
    actions = audit_actions(client)
    for action in ["api.plugins.validate", "api.plugins.install", "api.tasks.run", "api.reports.generate"]:
        result.check(f"audit contains {action}", action in actions, f"audit includes {action}")
    return result


def scenario_b(client: HttpClient) -> ScenarioResult:
    result = ScenarioResult("B", "高风险工具审批闭环")
    install_plugin(client, "example-restricted-high-risk", validate_first=True)
    payload = task_payload("scenario_b_restricted_high_risk.yaml")
    status, plan = client.request("POST", "/api/tasks/plan", VIEWER, payload)
    result.check("task plan", status == 200 and plan["executionOrder"] == ["restricted"], "restricted step is planned")
    status, policy = client.request("POST", "/api/policy/explain", VIEWER, payload)
    reason_text = json.dumps(policy, ensure_ascii=False)
    result.check(
        "approval required",
        status == 200 and policy[0]["decision"]["allowed"] is False and "approved request" in reason_text,
        "policy explain shows approval requirement for planned task",
    )
    status, denied = client.request("POST", "/api/tasks/run", OPERATOR, payload)
    result.check(
        "unapproved run denied",
        status == 403 and api_error_code(denied) == "AuthorizationDenied",
        "unapproved high-risk task is denied",
    )

    status, approval = client.request(
        "POST",
        "/api/approvals/request",
        OPERATOR,
        {"resource": "p55-full-restricted-high-risk", "risk": "high"},
    )
    result.check("request approval", status == 200 and approval["status"] == "pending", "approval request is pending")
    approval_id = approval["approvalId"]
    status, approved = client.request("POST", f"/api/approvals/{approval_id}/approve", APPROVER)
    result.check("approver approves", status == 200 and approved["status"] == "approved", "approval is approved")

    approved_payload = {
        "content": payload["content"].replace(
            "approveHighRisk: false",
            f"approveHighRisk: false\n    approvalRef: {approval_id}",
        )
    }
    status, run_body = client.request("POST", "/api/tasks/run", OPERATOR, approved_payload)
    result.check("operator executes approved task", status == 200 and run_body["status"] == "completed", "approved task completed")
    actions = audit_actions(client)
    for action in ["api.approvals.request", "api.approvals.approve", "api.tasks.run", "tool.run.finished"]:
        result.check(f"audit contains {action}", action in actions, f"audit includes {action}")
    return result


def scenario_c(client: HttpClient) -> ScenarioResult:
    result = ScenarioResult("C", "失败与部分失败闭环")
    install_many(client, ["example-invalid-parser", "example-slow"])
    payload = task_payload("scenario_c_failure_mixed.yaml")
    status, plan = client.request("POST", "/api/tasks/plan", VIEWER, payload)
    result.check(
        "task plan includes success invalid timeout",
        status == 200 and plan["executionOrder"] == ["success", "invalid-parser", "timeout"],
        "all three steps are planned",
    )
    status, body = client.request("POST", "/api/tasks/run", OPERATOR, payload, timeout=30)
    result.check(
        "task run reports controlled failure",
        status in {400, 500} and api_error_code(body) in {"SchemaValidationFailed", "RuntimeError"},
        "mixed failure task returns controlled error",
    )
    task = wait_for_task(client, "p55-full-failure-mixed", lambda value: value.get("status") == "failed")
    states = task["stepStates"]
    result.check("success step completed", states["fixture-one/success"] == "completed", "success step completed")
    result.check("invalid parser step failed", states["fixture-one/invalid-parser"] == "failed", "invalid parser failed")
    result.check("timeout step failed", states["fixture-one/timeout"] == "failed", "timeout step failed")
    markdown = generate_and_read_report(client, task["taskId"])
    lower_markdown = markdown.lower()
    result.check("report shows success", "Example echo completed" in markdown, "report includes successful finding")
    result.check("report shows parser error", "schemavalidationfailed" in lower_markdown or "normalization contract" in lower_markdown, "report includes parser error")
    result.check("report shows timeout error", "timeout" in lower_markdown or "timed out" in lower_markdown, "report includes timeout error")
    actions = audit_actions(client)
    for action in ["tool.run.finished", "tool.run.failed", "result.normalized", "api.reports.generate"]:
        result.check(f"audit contains {action}", action in actions, f"audit includes {action}")
    return result


def scenario_d(client: HttpClient) -> ScenarioResult:
    result = ScenarioResult("D", "取消任务闭环")
    payload = task_payload("scenario_d_cancel.yaml")
    run_response: dict[str, Any] = {}

    def run_task() -> None:
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, payload, timeout=30)
        run_response["status"] = status
        run_response["body"] = body

    thread = threading.Thread(target=run_task, daemon=True)
    thread.start()
    task = wait_for_task(
        client,
        "p55-full-cancel",
        lambda value: value.get("status") in {"planning", "running"}
        and value.get("stepStates", {}).get("fixture-one/slow") == "running",
        timeout=8,
    )
    task_id = task["taskId"]
    status, cancel_body = client.request("POST", f"/api/tasks/{task_id}/cancel", OPERATOR)
    result.check("user cancels task", status == 200 and cancel_body["status"] == "cancelling", "cancel request accepted")
    thread.join(timeout=15)
    result.check("run request finishes after cancellation", not thread.is_alive(), "background run returned")
    final_task = wait_for_task(client, "p55-full-cancel", lambda value: value.get("status") == "cancelled", timeout=8)
    states = final_task["stepStates"]
    result.check("state becomes cancelled", final_task["status"] == "cancelled", "task status is cancelled")
    result.check("subprocess cleanup is reflected", "running" not in set(states.values()), "no task step remains running")
    result.check(
        "run response is controlled cancellation",
        run_response.get("status") == 500 and api_error_code(run_response.get("body")) == "RuntimeError",
        "cancelled run reports controlled runtime error",
    )
    actions = audit_actions(client)
    result.check(
        "audit records cancellation",
        "task.cancel.requested" in actions or "api.tasks.cancel" in actions,
        "audit includes task.cancel.requested or api.tasks.cancel",
    )
    return result


def write_report(results: list[ScenarioResult], command: str, workspace: pathlib.Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# SentinelFlow P5.5 Full E2E Report",
        "",
        f"Generated: {now}",
        "",
        f"Command: `{command}`",
        f"Workspace: `{workspace}`",
        "",
        "## Scope",
        "",
        "This report covers deployment startup, Web login through the API-backed Console path, plugin validation/install, tool discovery, task planning, policy/approval, execution, realtime logs, findings, reports, audit, failure handling, and cancellation.",
        "",
        "All plugins are safe local fixtures. No public targets, real credentials, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.",
        "",
        "## Scenario Summary",
        "",
        "| Scenario | Description | Result |",
        "| --- | --- | --- |",
    ]
    for result in results:
        lines.append(f"| {result.name} | {result.description} | {'pass' if result.passed else 'fail'} |")
    lines.extend(["", "## Step Results", "", "| Scenario | Step | Result | Detail |", "| --- | --- | --- | --- |"])
    for result in results:
        for step in result.steps:
            detail = step.detail.replace("|", "\\|")
            lines.append(f"| {step.scenario} | {step.step} | {'pass' if step.passed else 'fail'} | {detail} |")
    lines.extend(
        [
            "",
            "## Release Decision",
            "",
            f"- Failed scenarios: `{sum(0 if result.passed else 1 for result in results)}`",
            "- Result: `pass`" if all(result.passed for result in results) else "- Result: `fail`",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    work_root = pathlib.Path(tempfile.mkdtemp(prefix="sentinelflow-p55-full-flow."))
    workspace = work_root / ".sentinelflow"
    port = os.environ.get("SENTINELFLOW_FULL_FLOW_PORT") or free_port()
    base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "SENTINELFLOW_API_BIND": f"127.0.0.1:{port}",
            "SENTINELFLOW_WORKSPACE_DIR": str(workspace),
            "SENTINELFLOW_SCHEMA_ROOT": str(ROOT),
        }
    )
    server = subprocess.Popen(
        [str(API)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    results: list[ScenarioResult] = []
    try:
        client = HttpClient(base)
        wait_for_health(client)
        for scenario in [scenario_a, scenario_b, scenario_c, scenario_d]:
            results.append(scenario(client))
        write_report(results, "tests/e2e/p5_5_full_flow/run.sh", workspace)
        failed = [result.name for result in results if not result.passed]
        if failed:
            print(json.dumps({"status": "failed", "failed": failed, "report": str(REPORT)}, indent=2))
            return 1
        print(json.dumps({"status": "ok", "scenarios": len(results), "report": str(REPORT)}, indent=2))
        return 0
    except Exception as error:
        failed_result = ScenarioResult("runner", "E2E runner failure")
        failed_result.steps.append(StepResult("runner", "exception", False, str(error)))
        results.append(failed_result)
        write_report(results, "tests/e2e/p5_5_full_flow/run.sh", workspace)
        print(json.dumps({"status": "failed", "error": str(error), "report": str(REPORT)}, indent=2))
        return 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
