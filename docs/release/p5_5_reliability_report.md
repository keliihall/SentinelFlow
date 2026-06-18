# SentinelFlow P5.5 Reliability Report

Generated: 2026-06-17T01:47:21Z

Command: `tests/e2e/p5_5_reliability/run.sh`
Workspace: `/var/folders/46/j153v48s4dqg3wg85sg3g4mw0000gn/T/sentinelflow-p55-reliability.hn6vr2zw/.sentinelflow`

## Scope

This report covers task state-machine auditability, controlled abnormal execution, service restart recovery, SSE log reconnect, duplicate user actions, report failure handling, and persisted error codes.

All checks use local safe fixtures only. No real targets, credentials, scanners, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.

## Result Summary

| Category | Expected Reliability Behavior | Result | Evidence |
| --- | --- | --- | --- |
| completed 状态审计 | 成功任务进入 completed 且有 task.state.completed | pass | status=200 task=task-755c5f28-5554-46b2-b0af-f1869108cd02 |
| 日志断线重连 | 重连后 cursor 单调递增且不重复 | pass | first=[1, 2] second=[3, 4] |
| API 服务重启 | 重启后可查询已有任务和日志 | pass | task=200 logs=200:12 |
| approval_required 状态 | 未审批高风险任务不 stuck，落到 approvalRequired 并保留错误码 | pass | status=403 taskStatus=approvalRequired code=AuthorizationDenied |
| 失败状态错误码 | Parser/Normalizer/timeout 失败落到 failed 且有 lastError | pass | status=400 code=SchemaValidationFailed |
| Report 生成失败 | 报告失败返回标准错误且写入 failed audit | pass | status=500 code=SystemError |
| 重复提交审批 | 重复 approve 安全拒绝且审批状态不污染 | pass | first=200 second=403 final=approved |
| 用户重复点击执行 | 运行中的同名任务重复 run 被 409 拒绝且不重复执行 | pass | dup=409 cancel=200 final=cancelled |
| 配置运行中漂移 | 任务恢复/运行基于 planSnapshot，漂移会被状态机失败路径捕获 | pass | plan snapshot is verified at scheduler start; mismatch marks task.state.failed |
| 子进程和输出异常契约 | timeout/异常退出/超大 stdout stderr/取消清理由 adapter contract 覆盖 | pass | covered by crates/sentinelflow-adapter-command/tests/runtime_contract.rs |
| Store/Audit 写入失败契约 | Store 和 Audit 写入错误返回 SystemError，不吞异常 | pass | covered by sentinelflow-store unit tests |

## State Machine Audit

| State | Audit Action |
| --- | --- |
| pending | `task.state.pending` |
| planning | `task.state.planning` |
| approval_required | `task.state.approval_required` |
| running | `task.state.running` |
| paused | `task.state.paused` |
| cancelling | `task.state.cancelling` |
| cancelled | `task.state.cancelled` |
| failed | `task.state.failed` |
| completed | `task.state.completed` |

## Abnormal Path Coverage

- Subprocess timeout, abnormal exit, oversized stdout/stderr, output limit, cancellation cleanup, and environment allowlist are covered by `crates/sentinelflow-adapter-command/tests/runtime_contract.rs` and the workspace test gate.
- Parser invalid output and normalization contract failures are exercised through `example-invalid-parser` in this E2E.
- Store write and Audit write failure behavior is covered by `sentinelflow-store` unit tests and the workspace test gate.
- Report generation failure is exercised through the API with a missing task and must emit failed audit.

## Release Decision

- Failed checks: `0`
- Result: `pass`
