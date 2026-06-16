# SentinelFlow P5.5 Full E2E Report

Generated: 2026-06-16T04:26:27Z

Command: `tests/e2e/p5_5_full_flow/run.sh`
Workspace: `/var/folders/46/j153v48s4dqg3wg85sg3g4mw0000gn/T/sentinelflow-p55-full-flow.m9k5m0a8/.sentinelflow`

## Scope

This report covers deployment startup, Web login through the API-backed Console path, plugin validation/install, tool discovery, task planning, policy/approval, execution, realtime logs, findings, reports, audit, failure handling, and cancellation.

All plugins are safe local fixtures. No public targets, real credentials, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.

## Scenario Summary

| Scenario | Description | Result |
| --- | --- | --- |
| A | 低风险工具执行闭环 | pass |
| B | 高风险工具审批闭环 | pass |
| C | 失败与部分失败闭环 | pass |
| D | 取消任务闭环 | pass |

## Step Results

| Scenario | Step | Result | Detail |
| --- | --- | --- | --- |
| A | open Web Console | pass | console page is served |
| A | login Web | pass | operator login issues development token |
| A | initialize system | pass | health endpoint is ready |
| A | validate plugin | pass | example-echo validates |
| A | install plugin | pass | example-echo installed |
| A | view tool list | pass | tool list includes example-echo |
| A | create and validate low-risk Task Spec | pass | Task Spec validates |
| A | task plan | pass | plan is deterministic |
| A | execute task | pass | low-risk task completed |
| A | view realtime logs | pass | SSE stream emits audit event |
| A | view Finding | pass | finding includes fingerprint |
| A | generate report | pass | report includes finding summary |
| A | audit contains api.plugins.validate | pass | audit includes api.plugins.validate |
| A | audit contains api.plugins.install | pass | audit includes api.plugins.install |
| A | audit contains api.tasks.run | pass | audit includes api.tasks.run |
| A | audit contains api.reports.generate | pass | audit includes api.reports.generate |
| B | task plan | pass | restricted step is planned |
| B | approval required | pass | policy explain shows approval requirement for planned task |
| B | unapproved run denied | pass | unapproved high-risk task is denied |
| B | request approval | pass | approval request is pending |
| B | approver approves | pass | approval is approved |
| B | operator executes approved task | pass | approved task completed |
| B | audit contains api.approvals.request | pass | audit includes api.approvals.request |
| B | audit contains api.approvals.approve | pass | audit includes api.approvals.approve |
| B | audit contains api.tasks.run | pass | audit includes api.tasks.run |
| B | audit contains tool.run.finished | pass | audit includes tool.run.finished |
| C | task plan includes success invalid timeout | pass | all three steps are planned |
| C | task run reports controlled failure | pass | mixed failure task returns controlled error |
| C | success step completed | pass | success step completed |
| C | invalid parser step failed | pass | invalid parser failed |
| C | timeout step failed | pass | timeout step failed |
| C | report shows success | pass | report includes successful finding |
| C | report shows parser error | pass | report includes parser error |
| C | report shows timeout error | pass | report includes timeout error |
| C | audit contains tool.run.finished | pass | audit includes tool.run.finished |
| C | audit contains tool.run.failed | pass | audit includes tool.run.failed |
| C | audit contains result.normalized | pass | audit includes result.normalized |
| C | audit contains api.reports.generate | pass | audit includes api.reports.generate |
| D | user cancels task | pass | cancel request accepted |
| D | run request finishes after cancellation | pass | background run returned |
| D | state becomes cancelled | pass | task status is cancelled |
| D | subprocess cleanup is reflected | pass | no task step remains running |
| D | run response is controlled cancellation | pass | cancelled run reports controlled runtime error |
| D | audit records cancellation | pass | audit includes task.cancel.requested or api.tasks.cancel |

## Release Decision

- Failed scenarios: `0`
- Result: `pass`
