# SentinelFlow P5.5 Consistency Report

Generated: 2026-06-16T01:26:04Z

Command: `tests/e2e/p5_5_consistency.sh`

## Scope

This report verifies CLI/API/Web consistency for the same Task Spec, Policy, and safe example plugins. The Web Console is verified as an API-only entry: it does not implement Policy or execution logic locally, and its user-visible workflow is backed by the same API endpoints compared against CLI outcomes.

Because Web must not duplicate Policy or execution logic, per-fixture Web semantics are represented by the API endpoint results after the Console endpoint wiring and API-only boundary checks pass.

## Web Entry

| Check | Result |
| --- | --- |
| Console served | pass |
| API-only statement present | pass |
| Required workflow API endpoints present | pass |
| No direct execution/policy fragments | pass |

## Fixture Results

| Fixture | Description | Validate | Plan | Policy | Run | Findings | Report | Audit | Result |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- |
| low-risk | 合法低风险任务 | pass | pass | pass | pass | 2 | pass | pass | pass |
| unauthorized-target | 未授权目标任务 | pass | pass | pass | pass | 0 | pass | pass | pass |
| high-risk-unapproved | 高风险未审批任务 | pass | pass | pass | pass | 0 | pass | pass | pass |
| cross-midnight-window | 跨午夜时间窗任务 | pass | pass | pass | pass | 1 | pass | pass | pass |
| parser-invalid-output | Parser 非法输出任务 | pass | pass | pass | pass | 0 | pass | pass | pass |
| partial-failure | 部分失败任务 | pass | pass | pass | pass | 1 | pass | pass | pass |

## Detailed Comparison

### low-risk

- CLI run status/error: `0` / `None`
- API run status/error: `200` / `None`
- Execution order: `['echo']`
- Step states: `{"fixture-one/echo": "completed", "fixture-two/echo": "completed"}`
- Finding fingerprints: `["550faaedb0f7b7f08186eb20b9b0235f8a4a322e05a99019b1d3e8b57aada5b6", "b2253bb86efbd4fef9105100d00505e39ca51d750e0d460018f25cdf1e2bb394"]`
- Core audit actions: `["report.generated", "result.normalized", "tool.run.finished", "tool.run.started"]`
- Differences: `[]`

### unauthorized-target

- CLI run status/error: `4` / `AuthorizationDenied`
- API run status/error: `403` / `AuthorizationDenied`
- Execution order: `['echo']`
- Step states: `{"fixture-two/echo": "pending"}`
- Finding fingerprints: `[]`
- Core audit actions: `["policy.denied"]`
- Differences: `[]`

### high-risk-unapproved

- CLI run status/error: `4` / `AuthorizationDenied`
- API run status/error: `403` / `AuthorizationDenied`
- Execution order: `['approval']`
- Step states: `{"fixture-one/approval": "pending"}`
- Finding fingerprints: `[]`
- Core audit actions: `["policy.denied"]`
- Differences: `[]`

### cross-midnight-window

- CLI run status/error: `0` / `None`
- API run status/error: `200` / `None`
- Execution order: `['echo']`
- Step states: `{"fixture-one/echo": "completed"}`
- Finding fingerprints: `["a7ca0dddf7ad935abb0246991efd6c74a8c9d495eb5c112cb9fd46ef27c980ed"]`
- Core audit actions: `["report.generated", "result.normalized", "tool.run.finished", "tool.run.started"]`
- Differences: `[]`

### parser-invalid-output

- CLI run status/error: `3` / `SchemaValidationFailed`
- API run status/error: `400` / `SchemaValidationFailed`
- Execution order: `['invalid-parser']`
- Step states: `{"fixture-one/invalid-parser": "failed"}`
- Finding fingerprints: `[]`
- Core audit actions: `["result.normalized", "tool.run.failed", "tool.run.finished", "tool.run.started"]`
- Differences: `[]`

### partial-failure

- CLI run status/error: `5` / `RuntimeError`
- API run status/error: `500` / `RuntimeError`
- Execution order: `['fails', 'independent', 'dependent']`
- Step states: `{"fixture-one/dependent": "skipped", "fixture-one/fails": "failed", "fixture-one/independent": "completed"}`
- Finding fingerprints: `["3559b817e66e98d75f3f28a11f5e42dd911ef79c39a6d402868912dd0683345d"]`
- Core audit actions: `["report.generated", "result.normalized", "tool.run.failed", "tool.run.finished", "tool.run.started"]`
- Differences: `[]`

## Release Decision

- Blocker/High consistency differences: `0`
- Result: `pass`
