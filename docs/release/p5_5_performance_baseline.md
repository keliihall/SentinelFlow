# SentinelFlow P5.5 Performance Baseline

Generated: 2026-06-15

## Scope

This baseline covers the v1.0-rc single-node shape: API Service, Web Console,
CLI/Core orchestration, SQLite store, audit log, normalized findings, task logs,
and Markdown reports. The workload is synthetic and local-only. It uses
`example-echo` and does not generate real attack traffic, scan external targets,
disable audit, or bypass schema validation/normalization.

Repeat the baseline with:

```sh
tests/performance/run.sh
```

The script writes raw metrics to
`docs/release/p5_5_performance_baseline_metrics.json`.

## Scenarios

| Scenario | Coverage |
| --- | --- |
| Concurrent Web/API access | Mixed `/console`, `/health`, `/api/session`, tools, audit, and findings reads. |
| Concurrent task plan | Parallel `POST /api/tasks/plan` over safe Task Specs. |
| Concurrent low-risk mock task run | Parallel `POST /api/tasks/run` using `example-echo`. |
| Finding import pressure | 128 additional Findings are produced through a multi-target `example-echo` task and read through paged `/api/findings`. |
| Audit Event pressure | Authenticated API reads write Audit Events with audit enabled. |
| Real-time log stream concurrency | Parallel SSE clients connect to `/api/tasks/{taskId}/logs/stream`. |
| Batch report generation | Multiple task reports are generated through `POST /api/reports/generate`. |

## Latest Local Result

Command:

```sh
tests/performance/run.sh
```

Result: passed.

| Metric | Observed |
| --- | ---: |
| API latency P50 / P95 / P99 | 35.50 ms / 153.45 ms / 400.30 ms |
| Task plan P50 / P95 / P99 | 55.73 ms / 165.31 ms / 219.62 ms |
| Task run scheduling P50 / P95 / P99 | 946.72 ms / 1036.79 ms / 1036.79 ms |
| Bulk Finding task duration | 5555.36 ms for 128 additional targets |
| Log push P50 / P95 / P99 | 27.71 ms / 61.11 ms / 61.11 ms |
| Finding query latency | 12.59 ms for 136 findings |
| Finding write throughput | 20.63 findings/s through normal task execution |
| Audit write throughput | 195.56 requested audit writes/s |
| Report generation P50 / P95 / P99 | 25.25 ms / 29.26 ms / 29.26 ms |
| API RSS growth | 7.6 MiB to 29.5 MiB |
| Workspace growth | 73,050 bytes to 1,775,503 bytes |
| SQLite database size | 1,048,576 bytes |

## v1.0-rc Capacity Baseline

Recommended single-node pilot specification:

| Resource | Recommendation |
| --- | --- |
| CPU | 2 vCPU minimum, 4 vCPU recommended for concurrent pilots. |
| Memory | 2 GiB minimum, 4 GiB recommended. |
| Disk | 10 GiB local SSD minimum; monitor `.sentinelflow/results`, `reports`, `audit`, and `state.db`. |
| Backend | SQLite only for v1.0-rc. PostgreSQL settings are reserved and not active. |

Recommended workload limits:

| Boundary | v1.0-rc Recommendation |
| --- | ---: |
| Concurrent task runs per single node | 4 recommended, 8 upper pilot limit for low-risk mock workloads. |
| Concurrent API/Web users | 20 recommended, 50 upper pilot limit. |
| Single task findings | 1,000 recommended. |
| Single task log events | 2,000 recommended. |
| Single report findings | 5,000 hard default API guard. |
| List API default page size | 100 items. |
| List API maximum page size | 500 items. |
| Task log list default page size | 200 events. |
| Task log list/SSE maximum page size | 1,000 events. |
| Default safe task timeout | 5-30 seconds for example workloads; keep production-like pilots below 300 seconds. |

## Bottlenecks And Fixes

- List endpoints are now bounded with `limit`/`offset` on tasks, runs, findings,
  reports, approvals, audit, and task logs.
- Task log SSE reads only the next bounded page instead of reloading all
  historical audit events on each poll.
- Web Console list/log buttons request explicit page limits so large workspaces
  are not rendered in one browser update.
- Audit Event writes now append to `audit/events.jsonl` and index selected fields
  in SQLite instead of rewriting the entire JSONL file for every event.
- SQLite schema version `3` adds indexed `task_id`, `resource_ref`, and
  `actor_id` audit fields plus indexes for task/runs/findings/audit lookups.
- API task run duplicate detection and latest-task lookup use SQLite indexes
  rather than full task artifact scans.
- Report generation checks finding counts before loading report bundles and
  rejects reports above the v1.0-rc limit with a standard runtime error.

## SQLite/PostgreSQL Position

SQLite is the active v1.0-rc backend. The baseline shows SQLite is sufficient for
small local pilots, but write serialization is the main capacity boundary under
heavy audit and result writes. PostgreSQL is intentionally not enabled in
v1.0-rc; any PostgreSQL setting is reserved configuration only and must not be
treated as a fallback backend.

## Release Decision

P5.5-07 acceptance is satisfied for a single-node v1.0-rc pilot when the full
workspace gates and `tests/performance/run.sh` pass. The recommended limits above
should be treated as product limits, not just test values.
