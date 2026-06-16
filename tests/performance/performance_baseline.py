#!/usr/bin/env python3
"""Repeatable local performance baseline for SentinelFlow v1.0-rc.

The workload is intentionally synthetic and local-only. It exercises the public
CLI/API/Web paths with example-echo and never sends traffic to external targets.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "target" / "debug" / "sentinelflow"
API = ROOT / "target" / "debug" / "sentinelflow-api"
REPORT_PATH = ROOT / "docs" / "release" / "p5_5_performance_baseline_metrics.json"
OPERATOR = "operator-token"
VIEWER = "viewer-token"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-users", type=int, default=12)
    parser.add_argument("--plans", type=int, default=24)
    parser.add_argument("--runs", type=int, default=8)
    parser.add_argument("--bulk-findings", type=int, default=128)
    parser.add_argument("--audit-events", type=int, default=120)
    parser.add_argument("--sse-clients", type=int, default=8)
    parser.add_argument("--reports", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--keep-workspace", action="store_true")
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_command(args: list[str], *, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def request(
    base_url: str,
    method: str,
    path: str,
    token: str | None = None,
    body: Any | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes, float]:
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read()
            return response.status, payload, elapsed_ms(started)
    except urllib.error.HTTPError as error:
        payload = error.read()
        return error.code, payload, elapsed_ms(started)


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(
        len(ordered) - 1,
        max(0, int(round((percentile_value / 100.0) * (len(ordered) - 1)))),
    )
    return round(ordered[index], 2)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "p50Ms": percentile(values, 50),
        "p95Ms": percentile(values, 95),
        "p99Ms": percentile(values, 99),
        "maxMs": round(max(values), 2) if values else 0.0,
    }


def decode_json(payload: bytes) -> Any:
    return json.loads(payload.decode("utf-8"))


def task_spec(name: str, message: str) -> str:
    return f"""apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: {name}
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: {message}
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets:
      - fixture-one
    approveHighRisk: false
    timeoutSeconds: 5
    maxConcurrency: 1
    rateLimitPerMinute: 120
extensions: {{}}
"""


def bulk_finding_task_spec(name: str, finding_count: int) -> str:
    targets = []
    allowed = []
    for index in range(finding_count):
        target = f"fixture-{index:04d}"
        allowed.append(f"      - {target}")
        targets.extend(
            [
                f"    - name: {target}",
                "      input:",
                f"        message: bulk finding {index}",
            ]
        )
    return f"""apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: {name}
spec:
  authorizationScope: fixture:local-only
  targets:
{chr(10).join(targets)}
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets:
{chr(10).join(allowed)}
    approveHighRisk: false
    timeoutSeconds: 5
    maxConcurrency: 4
    rateLimitPerMinute: 600
extensions: {{}}
"""


def wait_for_api(base_url: str, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise RuntimeError(f"API exited early\nstdout:\n{stdout}\nstderr:\n{stderr}")
        try:
            status, _, _ = request(base_url, "GET", "/health", timeout=1.0)
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError("API did not become healthy")


def workspace_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            total += (Path(root) / name).stat().st_size
    return total


def process_rss_kib(pid: int) -> int:
    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        return 0
    text = completed.stdout.strip()
    return int(text) if text else 0


def count_audit_rows(workspace: Path) -> int:
    audit = workspace / "audit" / "events.jsonl"
    if not audit.exists():
        return 0
    return sum(1 for line in audit.read_text(encoding="utf-8").splitlines() if line.strip())


def first_sse_event_ms(base_url: str, task_id: str) -> tuple[int, float]:
    path = f"/api/tasks/{task_id}/logs/stream?cursor=0&limit=1&token={VIEWER}"
    req = urllib.request.Request(base_url + path, method="GET")
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=10.0) as response:
        while True:
            line = response.readline()
            if not line:
                break
            if line.startswith(b"data:"):
                return response.status, elapsed_ms(started)
    return 599, elapsed_ms(started)


def main() -> int:
    args = parse_args()
    temporary = tempfile.TemporaryDirectory(prefix="sentinelflow-perf-")
    workspace = Path(temporary.name) / ".sentinelflow"
    base_url = f"http://127.0.0.1:{free_port()}"
    env = os.environ.copy()
    env.update(
        {
            "SENTINELFLOW_API_BIND": base_url.removeprefix("http://"),
            "SENTINELFLOW_WORKSPACE_DIR": str(workspace),
            "SENTINELFLOW_SCHEMA_ROOT": str(ROOT),
        }
    )
    api_process: subprocess.Popen[str] | None = None
    try:
        run_command([str(CLI), "--workspace", str(workspace), "init"])
        run_command(
            [
                str(CLI),
                "--workspace",
                str(workspace),
                "plugin",
                "install",
                "plugins/examples/example-echo",
            ]
        )
        api_process = subprocess.Popen(
            [str(API)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        wait_for_api(base_url, api_process, args.timeout)
        start_size = workspace_size(workspace)
        start_rss = process_rss_kib(api_process.pid)

        lock = threading.Lock()
        api_latencies: list[float] = []

        def api_hit(index: int) -> float:
            endpoint = [
                "/console",
                "/health",
                "/api/session",
                "/api/tools?limit=100",
                "/api/audit?limit=20",
                "/api/findings?limit=100",
            ][index % 6]
            token = None if endpoint in {"/console", "/health"} else VIEWER
            status, _, duration = request(base_url, "GET", endpoint, token)
            if status >= 400:
                raise RuntimeError(f"API hit failed {endpoint}: {status}")
            with lock:
                api_latencies.append(duration)
            return duration

        def plan_hit(index: int) -> float:
            status, payload, duration = request(
                base_url,
                "POST",
                "/api/tasks/plan",
                VIEWER,
                {"content": task_spec(f"perf-plan-{index}", f"plan {index}")},
            )
            if status != 200:
                raise RuntimeError(f"plan failed {status}: {payload!r}")
            return duration

        def run_hit(index: int) -> tuple[str, float]:
            status, payload, duration = request(
                base_url,
                "POST",
                "/api/tasks/run",
                OPERATOR,
                {"content": task_spec(f"perf-run-{index}", f"run {index}")},
                timeout=args.timeout,
            )
            if status != 200:
                raise RuntimeError(f"run failed {status}: {payload!r}")
            return decode_json(payload)["taskId"], duration

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.api_users) as executor:
            list(executor.map(api_hit, range(args.api_users * 4)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.plans, 16)) as executor:
            plan_latencies = list(executor.map(plan_hit, range(args.plans)))

        run_started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.runs, 8)) as executor:
            run_results = list(executor.map(run_hit, range(args.runs)))
        run_total_ms = elapsed_ms(run_started)
        task_ids = [task_id for task_id, _ in run_results]
        run_latencies = [duration for _, duration in run_results]

        bulk_status, bulk_payload, bulk_duration = request(
            base_url,
            "POST",
            "/api/tasks/run",
            OPERATOR,
            {
                "content": bulk_finding_task_spec(
                    "perf-bulk-findings", args.bulk_findings
                )
            },
            timeout=max(args.timeout, 60.0),
        )
        if bulk_status != 200:
            raise RuntimeError(f"bulk finding run failed {bulk_status}: {bulk_payload!r}")
        task_ids.append(decode_json(bulk_payload)["taskId"])

        audit_started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda index: api_hit(index), range(args.audit_events)))
        audit_total_ms = elapsed_ms(audit_started)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.sse_clients) as executor:
            sse_results = list(
                executor.map(
                    lambda index: first_sse_event_ms(base_url, task_ids[index % len(task_ids)]),
                    range(args.sse_clients),
                )
            )
        sse_latencies = [duration for status, duration in sse_results if status == 200]

        status, payload, finding_query_ms = request(
            base_url, "GET", "/api/findings?limit=500", VIEWER
        )
        if status != 200:
            raise RuntimeError(f"findings query failed {status}: {payload!r}")
        finding_count = len(decode_json(payload))
        finding_write_ms = run_total_ms + bulk_duration

        report_started = time.perf_counter()
        report_latencies = []
        for task_id in task_ids[: args.reports]:
            status, payload, duration = request(
                base_url,
                "POST",
                "/api/reports/generate",
                OPERATOR,
                {"task": task_id},
                timeout=args.timeout,
            )
            if status != 200:
                raise RuntimeError(f"report failed {status}: {payload!r}")
            report_latencies.append(duration)
        report_total_ms = elapsed_ms(report_started)

        end_size = workspace_size(workspace)
        end_rss = process_rss_kib(api_process.pid)
        audit_rows = count_audit_rows(workspace)
        db_size = (workspace / "state.db").stat().st_size
        postgres_status = "not-active-in-v1.0-rc"
        metrics = {
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "workspace": str(workspace),
            "scenarios": {
                "concurrentApiUsers": args.api_users,
                "concurrentTaskPlans": args.plans,
                "concurrentMockTaskRuns": args.runs,
                "bulkFindingTaskTargets": args.bulk_findings,
                "findingRowsObserved": finding_count,
                "auditEventsRequested": args.audit_events,
                "sseClients": args.sse_clients,
                "reportsGenerated": len(report_latencies),
            },
            "metrics": {
                "apiLatency": summarize(api_latencies),
                "taskPlanLatency": summarize(plan_latencies),
                "taskRunSchedulingLatency": summarize(run_latencies),
                "taskRunBatchMs": round(run_total_ms, 2),
                "bulkFindingTaskMs": round(bulk_duration, 2),
                "logPushLatency": summarize(sse_latencies),
                "findingQueryLatencyMs": round(finding_query_ms, 2),
                "findingWriteThroughputPerSecond": round(
                    finding_count / max(finding_write_ms / 1000.0, 0.001), 2
                ),
                "auditWriteThroughputPerSecond": round(
                    args.audit_events / max(audit_total_ms / 1000.0, 0.001), 2
                ),
                "reportGenerationLatency": summarize(report_latencies),
                "reportBatchMs": round(report_total_ms, 2),
                "apiProcessRssKiB": {"start": start_rss, "end": end_rss},
                "workspaceBytes": {"start": start_size, "end": end_size},
                "sqliteBytes": db_size,
                "postgresqlWriteBottleneck": postgres_status,
                "auditRows": audit_rows,
            },
            "limits": {
                "safeWorkload": "local synthetic example-echo only",
                "externalTargets": "not used",
                "auditDisabled": False,
                "validationDisabled": False,
            },
        }
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(metrics, indent=2))
        return 0
    finally:
        if api_process is not None and api_process.poll() is None:
            api_process.terminate()
            try:
                api_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_process.kill()
                api_process.wait(timeout=5)
        if args.keep_workspace:
            print(f"kept workspace at {workspace}", file=sys.stderr)
        else:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
