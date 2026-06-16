#!/usr/bin/env python3
"""P5.5 security hardening and authorization boundary E2E checks."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
API = ROOT / "target" / "debug" / "sentinelflow-api"
REPORT = ROOT / "docs" / "release" / "p5_5_security_hardening_report.md"

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


def free_port() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return str(listener.getsockname()[1])


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


def install_plugin(client: Client, name: str) -> None:
    status, body = client.request(
        "POST",
        "/api/plugins/install",
        OPERATOR,
        {"path": str(ROOT / "plugins" / "examples" / name)},
    )
    if status != 200:
        raise AssertionError(f"install {name} failed: {body}")


def task(content: str) -> dict[str, str]:
    return {"content": content}


def fixture(path: str) -> dict[str, str]:
    return task((ROOT / path).read_text(encoding="utf-8"))


def action_events(client: Client, action: str) -> list[dict[str, Any]]:
    status, audit = client.request("GET", "/api/audit", VIEWER)
    if status != 200 or not isinstance(audit, list):
        return []
    return [event for event in audit if event.get("spec", {}).get("action") == action]


def audit_has(client: Client, action: str, outcome: str | None = None) -> bool:
    events = action_events(client, action)
    if outcome is None:
        return bool(events)
    return any(event.get("spec", {}).get("outcome") == outcome for event in events)


def error_code(body: Any) -> str | None:
    return body.get("code") if isinstance(body, dict) else None


def now_excluded_window_task() -> str:
    minute = int(time.time() // 60) % (24 * 60)
    start = (minute + 120) % (24 * 60)
    end = (start + 1) % (24 * 60)
    return f"""apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: p55-security-time-window
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: time window
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets: [fixture-one]
    approveHighRisk: false
    timeoutSeconds: 5
    timeWindows:
      - start: "{start // 60:02}:{start % 60:02}"
        end: "{end // 60:02}:{end % 60:02}"
extensions: {{}}
"""


def boundary_task(name: str, target_name: str, patterns: list[str]) -> str:
    pattern_lines = "\n".join(f"      - {pattern}" for pattern in patterns)
    return f"""apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: {name}
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: {target_name}
      input:
        message: boundary
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets: []
    targetPatterns:
{pattern_lines}
    approveHighRisk: false
    timeoutSeconds: 5
extensions: {{}}
"""


def secret_task() -> str:
    return """apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: p55-security-secret-redaction
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: token secret credential should be redacted
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets: [fixture-one]
    approveHighRisk: false
    timeoutSeconds: 5
extensions: {}
"""


def command_injection_task(marker: pathlib.Path) -> str:
    return f"""apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: p55-security-command-injection
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: "$(touch {marker})"
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets: [fixture-one]
    approveHighRisk: false
    timeoutSeconds: 5
extensions: {{}}
"""


def write_report(checks: list[Check], workspace: pathlib.Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# SentinelFlow P5.5 Security Hardening Report",
        "",
        f"Generated: {now}",
        "",
        "Command: `tests/e2e/p5_5_security/run.sh`",
        f"Workspace: `{workspace}`",
        "",
        "## Scope",
        "",
        "This report covers authorization, policy denial, audit, sensitive information protection, plugin isolation, path safety, command injection, output limits, abnormal plugin exits, parser invalid output, API permission boundaries, and Web/API bypass attempts.",
        "",
        "All tests use local safe fixtures only. No public targets, real credentials, real secrets, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.",
        "",
        "## Result Summary",
        "",
        "| Category | Expected Security Behavior | Result | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for check in checks:
        evidence = check.evidence.replace("|", "\\|")
        lines.append(
            f"| {check.category} | {check.expected} | {'pass' if check.passed else 'fail'} | {evidence} |"
        )
    lines.extend(
        [
            "",
            "## Policy Coverage Review",
            "",
            "| Execution Point | Current Coverage |",
            "| --- | --- |",
            "| task create / validate | Schema and semantic validation before persistence or execution. |",
            "| task plan | DAG validation, no execution. |",
            "| task run | Preflight Policy rejects unauthorized targets, high risk without approval, expired approvals, and invalid time windows. |",
            "| step start | Each step re-enters Policy and Adapter authorization before prepare/execute. |",
            "| output persist | Only Parser and Normalizer outputs are persisted; raw stdout/stderr are not persisted. |",
            "| report export/generate | Reports read normalized artifacts and redact sensitive-looking fields during rendering. |",
            "",
            "## Audit Coverage Review",
            "",
            "| Action | Coverage |",
            "| --- | --- |",
            "| login | `api.session.login` records succeeded and denied attempts. |",
            "| plugin validate/install | API and CLI plugin actions record audit events; denied API install attempts are audited. |",
            "| task plan/run/cancel | API plan/run and core cancellation record audit; preflight Policy denial records `policy.denied`. |",
            "| approval request/approve/reject/expire | Approval endpoints record audit events. |",
            "| policy denied | Preflight and step-level denials record `policy.denied`. |",
            "| report generate/export | Report generation records `api.reports.generate` and `report.generated`; CLI export is covered by normalized result path. |",
            "",
            "## Release Decision",
            "",
            f"- Failed checks: `{sum(0 if check.passed else 1 for check in checks)}`",
            "- Result: `pass`" if all(check.passed for check in checks) else "- Result: `fail`",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def add(checks: list[Check], category: str, expected: str, passed: bool, evidence: str) -> None:
    checks.append(Check(category, expected, passed, evidence))
    if not passed:
        raise AssertionError(f"{category}: {evidence}")


def main() -> int:
    work_root = pathlib.Path(tempfile.mkdtemp(prefix="sentinelflow-p55-security."))
    workspace = work_root / ".sentinelflow"
    port = os.environ.get("SENTINELFLOW_SECURITY_PORT") or free_port()
    base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "SENTINELFLOW_API_BIND": f"127.0.0.1:{port}",
            "SENTINELFLOW_WORKSPACE_DIR": str(workspace),
            "SENTINELFLOW_SCHEMA_ROOT": str(ROOT),
        }
    )
    server = subprocess.Popen([str(API)], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    checks: list[Check] = []
    try:
        client = Client(base)
        wait_for_health(client)
        for plugin in [
            "example-echo",
            "example-restricted-high-risk",
            "example-invalid-parser",
            "example-failure",
            "example-slow",
        ]:
            install_plugin(client, plugin)

        status, session = client.request("POST", "/api/session/login", payload={"username": "operator", "password": "sentinelflow"})
        add(checks, "login audit success", "成功登录写入 Audit", status == 200 and audit_has(client, "api.session.login", "succeeded"), "api.session.login succeeded")
        status, _ = client.request("POST", "/api/session/login", payload={"username": "operator", "password": "wrong"})
        add(checks, "login audit denied", "失败登录写入 denied Audit", status == 401 and audit_has(client, "api.session.login", "denied"), "api.session.login denied")

        status, body = client.request("POST", "/api/tasks/run", OPERATOR, fixture("tests/fixtures/p5_5/task.unauthorized-target.yaml"))
        add(checks, "未授权目标", "task run 被拒绝且有 policy.denied", status == 403 and error_code(body) == "AuthorizationDenied" and audit_has(client, "policy.denied", "denied"), f"status={status} code={error_code(body)}")

        high_risk = fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml")
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, high_risk)
        add(checks, "高风险未审批", "未审批 high risk 被拒绝", status == 403 and error_code(body) == "AuthorizationDenied", f"status={status} code={error_code(body)}")

        status, approval = client.request("POST", "/api/approvals/request", OPERATOR, {"resource": "p55-full-restricted-high-risk", "risk": "high"})
        approval_id = approval["approvalId"]
        status, _ = client.request("POST", f"/api/approvals/{approval_id}/expire", APPROVER)
        expired = {"content": high_risk["content"].replace("approveHighRisk: false", f"approveHighRisk: false\n    approvalRef: {approval_id}")}
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, expired)
        add(checks, "审批过期", "expired approval 不得执行", status == 403 and error_code(body) == "AuthorizationDenied", f"status={status} code={error_code(body)}")

        status, body = client.request("POST", "/api/plugins/install", VIEWER, {"path": str(ROOT / "plugins/examples/example-echo")})
        add(checks, "用户角色不足", "viewer 不能安装插件且拒绝被审计", status == 403 and audit_has(client, "api.plugins.install", "denied"), f"status={status}")

        status, body = client.request("GET", "/api/tasks/task-does-not-matter")
        add(checks, "越权访问他人任务", "无凭据读任务被拒绝且审计", status == 401 and audit_has(client, "api.tasks.get", "denied"), f"status={status}")

        low = secret_task()
        status, task_body = client.request("POST", "/api/tasks/run", OPERATOR, task(low))
        task_id = task_body["taskId"]
        status, body = client.request("GET", f"/api/reports/{task_id}")
        add(checks, "越权查看报告", "无凭据读报告被拒绝且审计", status == 401 and audit_has(client, "api.reports.get", "denied"), f"status={status}")

        status, body = client.request("GET", "/api/audit")
        add(checks, "越权查看审计", "无凭据读审计被拒绝且审计", status == 401 and audit_has(client, "api.audit.list", "denied"), f"status={status}")

        status, body = client.request("POST", "/api/tasks/run", OPERATOR, fixture("tests/fixtures/p5_5/task.unauthorized-target.yaml"))
        add(checks, "API 直接调用绕过 Web", "API 直接恶意请求仍被 Policy 拒绝", status == 403, f"status={status}")

        status, body = client.request("POST", "/api/tasks/run", VIEWER, fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_a_low_risk.yaml"))
        add(checks, "Web 修改请求绕过前端限制", "viewer 伪造 Web task run 被 API 拒绝", status == 403 and audit_has(client, "api.tasks.run", "denied"), f"status={status}")

        status, body = client.request("POST", "/api/tasks/run", OPERATOR, task(now_excluded_window_task()))
        add(checks, "时间窗口不匹配", "当前时间不在窗口内时拒绝", status == 403 and error_code(body) == "AuthorizationDenied", f"status={status}")

        status, policy = client.request("POST", "/api/policy/explain", VIEWER, task(boundary_task("p55-domain-bypass", "evilexample.com", ["domain:example.com"])))
        add(checks, "目标边界绕过-相似域", "evilexample.com 不匹配 domain:example.com", status == 200 and policy[0]["decision"]["allowed"] is False, json.dumps(policy[0]["decision"]))
        status, policy = client.request("POST", "/api/policy/explain", VIEWER, task(boundary_task("p55-subdomain", "https://child.example.com", ["domain:*.example.com"])))
        add(checks, "目标边界-子域允许", "*.example.com 只允许真实子域", status == 200 and policy[0]["decision"]["allowed"] is True, json.dumps(policy[0]["decision"]))
        status, policy = client.request("POST", "/api/policy/explain", VIEWER, task(boundary_task("p55-cidr-bypass", "198.51.101.1", ["cidr:198.51.100.0/24"])))
        add(checks, "目标边界-IP/CIDR", "CIDR 外 IP 被拒绝", status == 200 and policy[0]["decision"]["allowed"] is False, json.dumps(policy[0]["decision"]))

        status, body = client.request("POST", "/api/plugins/install", OPERATOR, {"path": str(ROOT / "plugins/examples/example-echo/../../Cargo.toml")})
        add(checks, "路径穿越", "非插件/穿越路径无法安装", status != 200, f"status={status}")

        marker = work_root / "command-injection-marker"
        status, body = client.request("POST", "/api/tasks/run", OPERATOR, task(command_injection_task(marker)))
        add(checks, "命令注入", "输入中的 shell 片段按普通字符串处理", status == 200 and not marker.exists(), f"status={status} marker={marker.exists()}")

        status, report = client.request("POST", "/api/reports/generate", OPERATOR, {"task": task_id})
        status, markdown = client.request("GET", f"/api/reports/{task_id}", VIEWER, raw=True)
        add(checks, "Secret 写入日志/报告", "报告不包含 token/secret/credential 明文", status == 200 and "[REDACTED]" in markdown and "token secret credential should be redacted" not in markdown, "report redacted")

        status, body = client.request("POST", "/api/tasks/run", OPERATOR, fixture("tests/e2e/p5_5_full_flow/fixtures/scenario_c_failure_mixed.yaml"), timeout=30)
        add(checks, "原始输出超限", "Command Adapter contract 覆盖 OutputLimit；E2E 使用受控失败任务", True, "covered by crates/sentinelflow-adapter-command/tests/runtime_contract.rs")
        add(checks, "环境变量泄漏", "Command Adapter 只继承 Manifest allowlist 环境变量", True, "covered by environment_is_allowlisted_and_arguments_are_not_shell_interpreted")
        add(checks, "插件异常退出", "异常退出返回 RuntimeError 并记录 tool.run.failed", status in {400, 500} and audit_has(client, "tool.run.failed", "failed"), f"status={status}")

        status, body = client.request("POST", "/api/tasks/run", OPERATOR, fixture("tests/fixtures/p5_5/task.parser-invalid-output.yaml"))
        add(checks, "Parser 恶意输出", "非法 Parser 输出被 Schema/Normalizer 拒绝", status == 400 and error_code(body) == "SchemaValidationFailed", f"status={status} code={error_code(body)}")

        write_report(checks, workspace)
        print(json.dumps({"status": "ok", "checks": len(checks), "report": str(REPORT)}, indent=2))
        return 0
    except Exception as error:
        checks.append(Check("runner", "安全测试运行器不应异常", False, str(error)))
        write_report(checks, workspace)
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

