# Results, Audit, and Reports

## Pipeline

P2-3 closes the safe example execution path:

```text
Command Adapter -> raw output reference -> trusted Parser -> Normalizer
                -> ToolOutput/Finding/Evidence/StandardError
                -> file artifacts + SQLite index -> export/report
```

The raw output reference is borrowed in memory. Raw stdout and stderr are not stored.
Parser output uses a strict JSON envelope; the Normalizer decodes it, constructs
versioned protocol resources, and performs semantic validation again.
The `fixture-invalid-output-v1` parser exists only as a synthetic failure fixture for
contract tests; it returns no operational data and proves malformed envelopes become
persisted `ParserOutputInvalid` errors plus failure audit events.

## Workspace Artifacts

For run `<run_id>`, SentinelFlow writes:

```text
.sentinelflow/runs/<run_id>.json
.sentinelflow/tasks/<task_id>.json
.sentinelflow/results/<run_id>.json
.sentinelflow/reports/<run_id>.md
.sentinelflow/audit/events.jsonl
.sentinelflow/state.db
```

Run and result JSON, reports, and the audit JSONL file use same-directory temporary
files followed by an atomic rename. `state.db` contains the minimum `tools`, `tasks`,
`runs`, `findings`, and `audit_events` tables. Files are the inspectable artifacts;
SQLite is the query index.

## Audit Events

The controlled run path emits:

- `tool.run.requested`
- `policy.denied`
- `tool.run.started`
- `tool.run.finished`
- `tool.run.failed`
- `result.normalized`
- `report.generated`

Run-related events include `taskId`, `runId`, `stepId`, `toolId`, `actorId`, and
`correlationId`. They do not include input, raw output, credentials, or secrets.

## Markdown Report

Reports contain Summary, Target, Tool, Findings, Evidence, Errors, and Audit Summary
sections. A run with zero findings or evidence still produces a complete report with
explicit empty-state text.

Task reports aggregate every target run and are written as
`.sentinelflow/reports/<task_id>.md`.

## Commands

```text
sentinelflow report generate --run <run_id>
sentinelflow report generate --task <task_id>
sentinelflow audit list
sentinelflow result export [--run <run_id>] --format json|jsonl|md
```
