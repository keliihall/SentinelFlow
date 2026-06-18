#!/usr/bin/env python3
"""P5.5 CLI/API/Web consistency verification.

The script drives the same safe fixtures through the CLI and API, verifies that
the Web Console is API-only, compares normalized semantic outcomes, and writes a
release report to docs/release/p5_5_consistency_report.md.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
CLI = ROOT / "target" / "debug" / "sentinelflow"
API = ROOT / "target" / "debug" / "sentinelflow-api"
REPORT = ROOT / "docs" / "release" / "p5_5_consistency_report.md"

PLUGINS = [
    "example-echo",
    "example-failure",
    "example-high-risk",
    "example-invalid-parser",
]

FIXTURES = [
    {
        "id": "low-risk",
        "path": "tests/fixtures/p5_5/task.low-risk.yaml",
        "description": "合法低风险任务",
        "expect_run": "allowed",
        "expect_report": True,
    },
    {
        "id": "unauthorized-target",
        "path": "tests/fixtures/p5_5/task.unauthorized-target.yaml",
        "description": "未授权目标任务",
        "expect_run": "denied",
        "expect_report": False,
    },
    {
        "id": "high-risk-unapproved",
        "path": "tests/fixtures/p5_5/task.high-risk-unapproved.yaml",
        "description": "高风险未审批任务",
        "expect_run": "denied",
        "expect_report": False,
    },
    {
        "id": "cross-midnight-window",
        "path": "tests/fixtures/p5_5/task.cross-midnight-window.yaml",
        "description": "跨午夜时间窗任务",
        "expect_run": "time-dependent",
        "expect_report": "if-allowed",
    },
    {
        "id": "parser-invalid-output",
        "path": "tests/fixtures/p5_5/task.parser-invalid-output.yaml",
        "description": "Parser 非法输出任务",
        "expect_run": "schema-error",
        "expect_report": False,
    },
    {
        "id": "partial-failure",
        "path": "tests/fixtures/p5_5/task.partial-failure.yaml",
        "description": "部分失败任务",
        "expect_run": "runtime-error",
        "expect_report": True,
    },
]


@dataclass
class CommandResult:
    status: int
    stdout: str
    stderr: str


def run(command: list[str], *, cwd: pathlib.Path = ROOT, env: dict[str, str] | None = None) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def json_or_none(text: str) -> Any | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def standard_error_kind(stderr: str) -> str | None:
    data = json_or_none(stderr)
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            return error.get("code")
    return None


def task_name(content: str) -> str | None:
    for index, line in enumerate(content.splitlines()):
        if line.strip() == "metadata:":
            for nested in content.splitlines()[index + 1 :]:
                stripped = nested.strip()
                if stripped.startswith("name:"):
                    return stripped.split(":", 1)[1].strip().strip('"').strip("'")
                if nested and not nested.startswith((" ", "\t")):
                    return None
    return None


def api_error_kind(status: int, body: Any) -> str | None:
    if status == 200:
        return None
    if isinstance(body, dict) and isinstance(body.get("code"), str):
        return body["code"]
    text = body.get("error", "") if isinstance(body, dict) else str(body)
    if status == 403:
        return "AuthorizationFailed"
    if status == 400 and "normalization contract" in text:
        return "SchemaValidationFailed"
    if status == 400:
        return "SchemaValidationFailed"
    if status == 500:
        return "RuntimeFailed"
    return f"HTTP{status}"


def http_request(base: str, method: str, path: str, token: str | None = None, payload: Any | None = None, raw: bool = False) -> tuple[int, Any]:
    headers: dict[str, str] = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
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


def cli_base(workspace: pathlib.Path) -> list[str]:
    return [
        str(CLI),
        "--workspace",
        str(workspace),
        "--schema-root",
        str(ROOT),
    ]


def install_cli_plugins(workspace: pathlib.Path) -> None:
    for plugin in PLUGINS:
        result = run(cli_base(workspace) + ["plugin", "install", str(ROOT / "plugins" / "examples" / plugin)])
        if result.status != 0:
            raise AssertionError(f"CLI plugin install failed for {plugin}: {result.stderr}")


def install_api_plugins(base: str) -> None:
    for plugin in PLUGINS:
        payload = {"path": str(ROOT / "plugins" / "examples" / plugin)}
        status, body = http_request(base, "POST", "/api/plugins/install", "operator-token", payload)
        if status != 200:
            raise AssertionError(f"API plugin install failed for {plugin}: {body}")


def newest_json(directory: pathlib.Path) -> dict[str, Any] | None:
    if not directory.exists():
        return None
    files = [path for path in directory.glob("*.json") if path.is_file()]
    if not files:
        return None
    latest = max(files, key=lambda path: path.stat().st_mtime_ns)
    return json.loads(latest.read_text())


def load_task_by_id(workspace: pathlib.Path, task_id: str | None) -> dict[str, Any] | None:
    if not task_id:
        return None
    path = workspace / "tasks" / f"{task_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def load_report(workspace: pathlib.Path, report_id: str | None) -> str | None:
    if not report_id:
        return None
    path = workspace / "reports" / f"{report_id}.md"
    return path.read_text() if path.exists() else None


def findings(workspace: pathlib.Path) -> list[dict[str, Any]]:
    directory = workspace / "results"
    found: list[dict[str, Any]] = []
    if not directory.exists():
        return found
    for path in sorted(directory.glob("*.json")):
        artifact = json.loads(path.read_text())
        output = artifact.get("output") or {}
        spec = output.get("spec") or {}
        found.extend(spec.get("findings") or [])
    return found


def audit_actions(workspace: pathlib.Path) -> list[str]:
    directory = workspace / "audit"
    if not directory.exists():
        return []
    actions: list[str] = []
    for path in sorted(directory.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            action = event.get("spec", {}).get("action")
            if action:
                actions.append(action)
    return actions


def action_correlation_ids(workspace: pathlib.Path) -> dict[str, list[str]]:
    directory = workspace / "audit"
    correlated: dict[str, list[str]] = {}
    if not directory.exists():
        return correlated
    for path in sorted(directory.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            spec = event.get("spec", {})
            action = spec.get("action")
            resource = spec.get("resourceRef")
            labels = event.get("metadata", {}).get("labels", {})
            correlation = labels.get("sentinelflow.io/correlation-id")
            candidate = correlation or resource
            if action and candidate:
                correlated.setdefault(action, []).append(candidate)
    return correlated


def normalize_policy(policy: Any) -> list[dict[str, Any]]:
    if not isinstance(policy, list):
        return []
    normalized = []
    for item in policy:
        decision = item.get("decision", {}) if isinstance(item, dict) else {}
        normalized.append(
            {
                "target": item.get("target"),
                "step": item.get("step"),
                "tool": item.get("tool"),
                "capability": item.get("capability"),
                "allowed": decision.get("allowed"),
                "reasons": decision.get("reasons") or [],
            }
        )
    return normalized


def semantic_error(status: int, cli_stderr: str = "", api_body: Any | None = None) -> str | None:
    if status == 0 or status == 200:
        return None
    if cli_stderr:
        kind = standard_error_kind(cli_stderr)
        if kind:
            return kind
        if status == 4:
            return "AuthorizationDenied"
        if status == 3:
            return "SchemaValidationFailed"
        if status == 5:
            return "RuntimeError"
    return api_error_kind(status, api_body)


def summarize_workspace(workspace: pathlib.Path, task_id: str | None, report_id: str | None) -> dict[str, Any]:
    task = load_task_by_id(workspace, task_id) or newest_json(workspace / "tasks") or {}
    found = findings(workspace)
    return {
        "taskId": task.get("taskId") or task_id,
        "taskStatus": task.get("status"),
        "executionOrder": task.get("planSnapshot", {}).get("executionOrder"),
        "stepStates": task.get("stepStates") or {},
        "findingCount": len(found),
        "fingerprints": sorted(finding.get("fingerprint") for finding in found if finding.get("fingerprint")),
        "reportGenerated": load_report(workspace, report_id or task.get("taskId")) is not None,
        "auditActions": audit_actions(workspace),
        "auditCorrelation": action_correlation_ids(workspace),
    }


def cli_fixture(workspace: pathlib.Path, fixture: dict[str, Any]) -> dict[str, Any]:
    task_path = ROOT / fixture["path"]
    validate = run(cli_base(workspace) + ["task", "validate", str(task_path)])
    plan_result = run(cli_base(workspace) + ["task", "plan", str(task_path)])
    policy_result = run(cli_base(workspace) + ["policy", "explain", str(task_path)])
    run_result = run(cli_base(workspace) + ["task", "run", str(task_path)])
    receipt = json_or_none(run_result.stdout)
    task_id = receipt.get("taskId") if isinstance(receipt, dict) else None
    if not task_id:
        task = newest_json(workspace / "tasks")
        task_id = task.get("taskId") if task else None
    report_status = None
    report_id = task_id
    if task_id and fixture["expect_report"] is not False:
        report_result = run(cli_base(workspace) + ["report", "generate", "--task", task_id])
        report_status = report_result.status
    summary = summarize_workspace(workspace, task_id, report_id)
    return {
        "validateOk": validate.status == 0,
        "validateStatus": validate.status,
        "planStatus": plan_result.status,
        "plan": json_or_none(plan_result.stdout),
        "policyStatus": policy_result.status,
        "policy": normalize_policy(json_or_none(policy_result.stdout)),
        "runStatus": run_result.status,
        "runError": semantic_error(run_result.status, cli_stderr=run_result.stderr),
        "reportStatus": report_status,
        **summary,
    }


def api_fixture(base: str, workspace: pathlib.Path, fixture: dict[str, Any]) -> dict[str, Any]:
    content = (ROOT / fixture["path"]).read_text()
    expected_task_name = task_name(content)
    payload = {"content": content}
    validate_status, validate_body = http_request(base, "POST", "/api/tasks/validate", "operator-token", payload)
    plan_status, plan_body = http_request(base, "POST", "/api/tasks/plan", "viewer-token", payload)
    policy_status, policy_body = http_request(base, "POST", "/api/policy/explain", "viewer-token", payload)
    run_status, run_body = http_request(base, "POST", "/api/tasks/run", "operator-token", payload)
    task_id = run_body.get("taskId") if isinstance(run_body, dict) else None
    if not task_id:
        tasks_status, tasks_body = http_request(base, "GET", "/api/tasks", "viewer-token")
        if tasks_status == 200 and isinstance(tasks_body, list) and tasks_body:
            candidates = [
                task
                for task in tasks_body
                if not expected_task_name or task.get("name") == expected_task_name
            ]
            if candidates:
                candidates.sort(key=lambda task: task.get("startedAt", ""))
                task_id = candidates[-1].get("taskId")
    report_status = None
    report_id = task_id
    if task_id and fixture["expect_report"] is not False:
        report_status, _ = http_request(base, "POST", "/api/reports/generate", "operator-token", {"task": task_id})
    http_request(base, "GET", "/api/findings", "viewer-token")
    http_request(base, "GET", "/api/audit", "viewer-token")
    summary = summarize_workspace(workspace, task_id, report_id)
    return {
        "validateOk": validate_status == 200 and isinstance(validate_body, dict) and validate_body.get("valid") is True,
        "validateStatus": validate_status,
        "planStatus": plan_status,
        "plan": plan_body if plan_status == 200 else None,
        "policyStatus": policy_status,
        "policy": normalize_policy(policy_body),
        "runStatus": run_status,
        "runError": semantic_error(run_status, api_body=run_body),
        "reportStatus": report_status,
        **summary,
    }


def web_entry(base: str) -> dict[str, Any]:
    status, html = http_request(base, "GET", "/console", raw=True)
    html = html if isinstance(html, str) else ""
    served_assets = [html]
    asset_statuses = {}
    for path in re.findall(r'<script[^>]+src="([^"]+)"', html):
        if not path.startswith("/console/"):
            continue
        asset_status, asset = http_request(base, "GET", path, raw=True)
        asset_statuses[path] = asset_status
        if asset_status == 200 and isinstance(asset, str):
            served_assets.append(asset)
    web_source = "\n".join(served_assets)
    required_endpoints = [
        "/api/tasks/validate",
        "/api/tasks/plan",
        "/api/policy/explain",
        "/api/tasks/run",
        "/api/findings",
        "/api/reports/generate",
        "/api/audit",
    ]
    forbidden_fragments = [
        "child_process",
        "Command::",
        "sentinelflow task run",
        "evaluate_task(",
        "policy.allowedTargets",
    ]
    return {
        "status": status if all(value == 200 for value in asset_statuses.values()) else 502,
        "apiOnlyStatement": "browser only calls the API service" in web_source,
        "requiredEndpointsPresent": all(endpoint in web_source for endpoint in required_endpoints),
        "noDirectExecutionFragments": not any(
            fragment in web_source for fragment in forbidden_fragments
        ),
    }


def compare_fixture(fixture: dict[str, Any], cli: dict[str, Any], api: dict[str, Any]) -> list[str]:
    differences: list[str] = []
    if cli["validateOk"] != api["validateOk"]:
        differences.append("task validate differs")
    if (cli["plan"] or {}).get("executionOrder") != (api["plan"] or {}).get("executionOrder"):
        differences.append("task plan executionOrder differs")
    if cli["policy"] != api["policy"]:
        differences.append("policy explain differs")
    cli_allowed = cli["runStatus"] == 0
    api_allowed = api["runStatus"] == 200
    if cli_allowed != api_allowed:
        differences.append("run allow/deny differs")
    if cli["runError"] != api["runError"]:
        differences.append(f"error kind differs: CLI={cli['runError']} API={api['runError']}")
    if cli["stepStates"] != api["stepStates"]:
        differences.append("step states differ")
    if cli["findingCount"] != api["findingCount"]:
        differences.append("finding count differs")
    if cli["fingerprints"] != api["fingerprints"]:
        differences.append("finding fingerprints differ")

    core_actions = {
        "tool.run.started",
        "tool.run.finished",
        "tool.run.failed",
        "policy.denied",
        "result.normalized",
        "report.generated",
    }
    cli_actions = set(cli["auditActions"]) & core_actions
    api_actions = set(api["auditActions"]) & core_actions
    expected_report = fixture["expect_report"]
    if expected_report is True or (expected_report == "if-allowed" and cli_allowed and api_allowed):
        if not (cli["reportGenerated"] and api["reportGenerated"]):
            differences.append("report generation differs")
    if cli_actions != api_actions:
        differences.append(f"core audit actions differ: CLI={sorted(cli_actions)} API={sorted(api_actions)}")
    for action in cli_actions | api_actions:
        if action in {"tool.run.started", "tool.run.finished", "tool.run.failed", "policy.denied", "result.normalized"}:
            if not cli["auditCorrelation"].get(action) or not api["auditCorrelation"].get(action):
                differences.append(f"audit correlation id missing for {action}")
    return differences


def write_report(results: list[dict[str, Any]], web: dict[str, Any], command: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# SentinelFlow P5.5 Consistency Report",
        "",
        f"Generated: {now}",
        "",
        f"Command: `{command}`",
        "",
        "## Scope",
        "",
        "This report verifies CLI/API/Web consistency for the same Task Spec, Policy, and safe example plugins. The Web Console is verified as an API-only entry: it does not implement Policy or execution logic locally, and its user-visible workflow is backed by the same API endpoints compared against CLI outcomes.",
        "",
        "Because Web must not duplicate Policy or execution logic, per-fixture Web semantics are represented by the API endpoint results after the Console endpoint wiring and API-only boundary checks pass.",
        "",
        "## Web Entry",
        "",
        "| Check | Result |",
        "| --- | --- |",
        f"| Console served | {'pass' if web['status'] == 200 else 'fail'} |",
        f"| API-only statement present | {'pass' if web['apiOnlyStatement'] else 'fail'} |",
        f"| Required workflow API endpoints present | {'pass' if web['requiredEndpointsPresent'] else 'fail'} |",
        f"| No direct execution/policy fragments | {'pass' if web['noDirectExecutionFragments'] else 'fail'} |",
        "",
        "## Fixture Results",
        "",
        "| Fixture | Description | Validate | Plan | Policy | Run | Findings | Report | Audit | Result |",
        "| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for result in results:
        cli = result["cli"]
        api = result["api"]
        diff = result["differences"]
        plan_ok = (cli["plan"] or {}).get("executionOrder") == (api["plan"] or {}).get("executionOrder")
        policy_ok = cli["policy"] == api["policy"]
        run_ok = (cli["runStatus"] == 0) == (api["runStatus"] == 200) and cli["runError"] == api["runError"]
        audit_ok = not any("audit" in item for item in diff)
        report_ok = not any("report" in item for item in diff)
        lines.append(
            "| {id} | {description} | {validate} | {plan} | {policy} | {run} | {findings} | {report} | {audit} | {result} |".format(
                id=result["fixture"]["id"],
                description=result["fixture"]["description"],
                validate="pass" if cli["validateOk"] and api["validateOk"] else "fail",
                plan="pass" if plan_ok else "fail",
                policy="pass" if policy_ok else "fail",
                run="pass" if run_ok else "fail",
                findings=cli["findingCount"],
                report="pass" if report_ok else "fail",
                audit="pass" if audit_ok else "fail",
                result="pass" if not diff else "fail",
            )
        )
    lines.extend(["", "## Detailed Comparison", ""])
    for result in results:
        fixture = result["fixture"]
        cli = result["cli"]
        api = result["api"]
        lines.extend(
            [
                f"### {fixture['id']}",
                "",
                f"- CLI run status/error: `{cli['runStatus']}` / `{cli['runError']}`",
                f"- API run status/error: `{api['runStatus']}` / `{api['runError']}`",
                f"- Execution order: `{(cli['plan'] or {}).get('executionOrder')}`",
                f"- Step states: `{json.dumps(cli['stepStates'], sort_keys=True)}`",
                f"- Finding fingerprints: `{json.dumps(cli['fingerprints'])}`",
                f"- Core audit actions: `{json.dumps(sorted(set(cli['auditActions']) & {'tool.run.started', 'tool.run.finished', 'tool.run.failed', 'policy.denied', 'result.normalized', 'report.generated'}))}`",
                f"- Differences: `{json.dumps(result['differences'], ensure_ascii=False)}`",
                "",
            ]
        )
    blockers = [result for result in results if result["differences"]]
    web_pass = (
        web["status"] == 200
        and web["apiOnlyStatement"]
        and web["requiredEndpointsPresent"]
        and web["noDirectExecutionFragments"]
    )
    lines.extend(
        [
            "## Release Decision",
            "",
            f"- Blocker/High consistency differences: `{len(blockers)}`",
            "- Result: `pass`" if not blockers and web_pass else "- Result: `fail`",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    workspace_root = pathlib.Path(tempfile.mkdtemp(prefix="sentinelflow-p55-consistency."))
    command = "tests/e2e/p5_5_consistency.sh"
    try:
        results = []
        web: dict[str, Any] | None = None
        base_port = int(os.environ.get("SENTINELFLOW_CONSISTENCY_PORT", "18081"))
        for index, fixture in enumerate(FIXTURES):
            fixture_root = workspace_root / fixture["id"]
            cli_workspace = fixture_root / "cli" / ".sentinelflow"
            api_workspace = fixture_root / "api" / ".sentinelflow"
            install_cli_plugins(cli_workspace)

            port = str(base_port + index)
            env = os.environ.copy()
            env.update(
                {
                    "SENTINELFLOW_API_BIND": f"127.0.0.1:{port}",
                    "SENTINELFLOW_WORKSPACE_DIR": str(api_workspace),
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
            try:
                base = f"http://127.0.0.1:{port}"
                for _ in range(100):
                    try:
                        status, health = http_request(base, "GET", "/health")
                        if status == 200 and health.get("status") == "ok":
                            break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise AssertionError("API service did not become healthy")

                install_api_plugins(base)
                if web is None:
                    web = web_entry(base)
                    web_pass = (
                        web["status"] == 200
                        and web["apiOnlyStatement"]
                        and web["requiredEndpointsPresent"]
                        and web["noDirectExecutionFragments"]
                    )
                    if not web_pass:
                        raise AssertionError(f"Web entry verification failed: {web}")

                cli_result = cli_fixture(cli_workspace, fixture)
                api_result = api_fixture(base, api_workspace, fixture)
                differences = compare_fixture(fixture, cli_result, api_result)
                results.append(
                    {
                        "fixture": fixture,
                        "cli": cli_result,
                        "api": api_result,
                        "differences": differences,
                    }
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
        assert web is not None
        write_report(results, web, command)
        failed = [result for result in results if result["differences"]]
        if failed:
            print(json.dumps({"status": "failed", "report": str(REPORT), "failed": [item["fixture"]["id"] for item in failed]}, indent=2))
            return 1
        print(json.dumps({"status": "ok", "report": str(REPORT), "fixtures": len(results)}, indent=2))
        return 0
    finally:
        shutil.rmtree(workspace_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
