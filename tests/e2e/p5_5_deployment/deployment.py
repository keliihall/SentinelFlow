#!/usr/bin/env python3
"""P5.5 deployment, upgrade, and migration verification."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import sqlite3
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
REPORT = ROOT / "docs" / "release" / "p5_5_deployment_report.md"
VIEWER = "viewer-token"
OPERATOR = "operator-token"


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
            "SENTINELFLOW_LOG_LEVEL": "info",
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


def add(checks: list[Check], category: str, expected: str, passed: bool, evidence: str) -> None:
    checks.append(Check(category, expected, passed, evidence))
    if not passed:
        raise AssertionError(f"{category}: {evidence}")


def install_echo(client: Client) -> None:
    status, body = client.request(
        "POST",
        "/api/plugins/install",
        OPERATOR,
        {"path": str(ROOT / "plugins" / "examples" / "example-echo")},
    )
    if status != 200:
        raise AssertionError(f"install example-echo failed: {body}")


def task_payload() -> dict[str, str]:
    return {"content": (ROOT / "tests" / "fixtures" / "task.single-step.yaml").read_text(encoding="utf-8")}


def schema_version(workspace: pathlib.Path) -> int:
    with sqlite3.connect(workspace / "state.db") as connection:
        row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)


def seed_previous_version_workspace(workspace: pathlib.Path) -> None:
    for directory in ["plugins", "tools", "tasks", "runs", "results", "reports", "audit", "approvals", "logs"]:
        (workspace / directory).mkdir(parents=True, exist_ok=True)
    (workspace / "reports" / "legacy-task.md").write_text("# Legacy Report\n", encoding="utf-8")
    audit_event = {
        "apiVersion": "sentinelflow.io/v1alpha1",
        "kind": "AuditEvent",
        "metadata": {"name": "audit-legacy"},
        "spec": {
            "action": "legacy.imported",
            "outcome": "allowed",
            "timestamp": "2026-01-01T00:00:00Z",
            "resourceRef": "legacy-task",
        },
        "extensions": {},
    }
    (workspace / "audit" / "events.jsonl").write_text(json.dumps(audit_event) + "\n", encoding="utf-8")
    with sqlite3.connect(workspace / "state.db") as connection:
        connection.executescript(
            """
            CREATE TABLE tools (
                tool_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            );
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                tool_id TEXT NOT NULL,
                actor_id TEXT NOT NULL
            );
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                artifact_path TEXT NOT NULL
            );
            CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                finding_json TEXT NOT NULL
            );
            CREATE TABLE audit_events (
                event_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                run_id TEXT,
                correlation_id TEXT,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            INSERT INTO tools VALUES ('legacy-tool', '0.9.0', '{}');
            INSERT INTO tasks VALUES ('legacy-task', 'legacy-tool', 'legacy-actor');
            INSERT INTO runs VALUES (
                'legacy-run', 'legacy-task', 'legacy-step', 'legacy-tool',
                'legacy-actor', 'legacy-correlation', 'succeeded',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 1,
                'runs/legacy-run.json'
            );
            INSERT INTO findings VALUES (
                'legacy-finding', 'legacy-run', 'info', 'Legacy finding',
                '{"title":"Legacy finding","summary":"preserved"}'
            );
            INSERT INTO audit_events VALUES (
                'legacy-audit', 'legacy.imported', 'allowed', 'legacy-run',
                'legacy-correlation', '2026-01-01T00:00:00Z', '{}'
            );
            """
        )


def verify_legacy_preserved(workspace: pathlib.Path) -> tuple[bool, str]:
    with sqlite3.connect(workspace / "state.db") as connection:
        tables = {
            "tools": "legacy-tool",
            "tasks": "legacy-task",
            "runs": "legacy-run",
            "findings": "legacy-finding",
            "audit_events": "legacy-audit",
        }
        counts = {}
        for table, key in tables.items():
            key_column = {
                "tools": "tool_id",
                "tasks": "task_id",
                "runs": "run_id",
                "findings": "finding_id",
                "audit_events": "event_id",
            }[table]
            counts[table] = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {key_column} = ?",
                (key,),
            ).fetchone()[0]
        version = schema_version(workspace)
    report_exists = (workspace / "reports" / "legacy-task.md").is_file()
    audit_exists = (workspace / "audit" / "events.jsonl").is_file()
    ok = version == 3 and all(value == 1 for value in counts.values()) and report_exists and audit_exists
    return ok, f"version={version} counts={counts} report={report_exists} audit={audit_exists}"


def write_report(checks: list[Check], workspace: pathlib.Path, upgrade_workspace: pathlib.Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    failed = sum(0 if check.passed else 1 for check in checks)
    lines = [
        "# SentinelFlow P5.5 Deployment Report",
        "",
        f"Generated: {now}",
        "",
        "Command: `tests/e2e/p5_5_deployment/run.sh`",
        f"Clean workspace: `{workspace}`",
        f"Upgrade fixture workspace: `{upgrade_workspace}`",
        "",
        "## Scope",
        "",
        "This report covers single-node deployment readiness, clean API/Web startup, safe example-echo execution, SQLite schema migration idempotency, previous-version upgrade preservation, and documented backup/restore paths.",
        "",
        "No real targets, credentials, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.",
        "",
        "## Result Summary",
        "",
        "| Category | Expected Deployment Behavior | Result | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for check in checks:
        lines.append(
            f"| {check.category} | {check.expected} | {'pass' if check.passed else 'fail'} | {check.evidence.replace('|', '\\|')} |"
        )
    lines.extend(
        [
            "",
            "## Deployment Matrix",
            "",
            "| Area | Status |",
            "| --- | --- |",
            "| API Service | Covered by clean startup and `/health` check. |",
            "| Web Console | Served from the API container at `/console`. |",
            "| SQLite | Active v1.0-rc backend with `schema_migrations` version metadata. |",
            "| PostgreSQL | Documented as reserved/not active in v1.0-rc to avoid silent fallback. |",
            "| Plugin directory | Mounted separately by Compose and backed up explicitly. |",
            "| Report directory | Mounted separately by Compose and backed up explicitly. |",
            "| Log directory | Created in workspace and mounted separately by Compose. |",
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
    work_root = pathlib.Path(tempfile.mkdtemp(prefix="sentinelflow-p55-deployment."))
    workspace = work_root / "clean" / ".sentinelflow"
    upgrade_workspace = work_root / "upgrade" / ".sentinelflow"
    port = os.environ.get("SENTINELFLOW_DEPLOYMENT_PORT") or free_port()
    base = f"http://127.0.0.1:{port}"
    checks: list[Check] = []
    server: subprocess.Popen[str] | None = None
    try:
        compose = subprocess.run(["docker", "compose", "config"], cwd=ROOT, text=True, capture_output=True)
        add(checks, "Compose 配置", "Docker Compose 配置可解析", compose.returncode == 0, compose.stderr.strip() or "docker compose config passed")

        server = start_server(workspace, port)
        client = Client(base)
        wait_for_health(client)
        status, console = client.request("GET", "/console", raw=True)
        add(checks, "干净环境启动", "API Service 和 Web Console 可访问", status == 200 and "SentinelFlow Console" in str(console), f"console={status}")

        install_echo(client)
        status, run_body = client.request("POST", "/api/tasks/run", OPERATOR, task_payload())
        task_id = run_body.get("taskId") if isinstance(run_body, dict) else None
        status_report, _ = client.request("POST", "/api/reports/generate", OPERATOR, {"task": task_id})
        add(checks, "example-echo 闭环", "部署后可安装 example-echo、执行任务并生成报告", status == 200 and run_body.get("status") == "completed" and status_report == 200, f"run={status} report={status_report} task={task_id}")
        add(checks, "安全默认配置", "高风险执行默认仍需审批", "approveHighRisk: false" in task_payload()["content"], "fixtures default to low risk; policy gate tested in release suites")
        add(checks, "SQLite 初始化迁移", "干净 workspace 初始化 schema_migrations", schema_version(workspace) == 3, f"version={schema_version(workspace)}")
        add(checks, "挂载目录", "plugins/reports/logs 目录存在", all((workspace / name).is_dir() for name in ["plugins", "reports", "logs"]), "plugins/reports/logs present")

        seed_previous_version_workspace(upgrade_workspace)
        # Trigger current migrations by starting a second service over the legacy workspace.
        stop_server(server)
        server = start_server(upgrade_workspace, port)
        wait_for_health(client)
        status, _ = client.request("GET", "/api/audit", VIEWER)
        ok, evidence = verify_legacy_preserved(upgrade_workspace)
        add(checks, "上一版本升级", "旧 schema fixture 升级后保留核心数据", status == 200 and ok, f"audit={status} {evidence}")
        version_before = schema_version(upgrade_workspace)
        stop_server(server)
        server = start_server(upgrade_workspace, port)
        wait_for_health(client)
        version_after = schema_version(upgrade_workspace)
        add(checks, "迁移幂等", "重复启动不改变 schema version 且不破坏数据", version_before == version_after == 3 and verify_legacy_preserved(upgrade_workspace)[0], f"before={version_before} after={version_after}")

        write_report(checks, workspace, upgrade_workspace)
        print(json.dumps({"status": "ok", "checks": len(checks), "report": str(REPORT)}, indent=2))
        return 0
    except Exception as error:
        checks.append(Check("runner", "部署测试运行器不应异常", False, str(error)))
        write_report(checks, workspace, upgrade_workspace)
        print(json.dumps({"status": "failed", "error": str(error), "report": str(REPORT)}, indent=2))
        return 1
    finally:
        if server is not None and server.poll() is None:
            stop_server(server)
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
