# SentinelFlow Troubleshooting

This guide uses safe local fixtures only. Do not troubleshoot by disabling Policy,
Audit, Parser, Normalizer, or Schema validation.

## Plugin Validation Fails

Run:

```sh
target/debug/sentinelflow plugin validate plugins/examples/example-echo
```

Check the reported stage:

| Stage | Common cause | Fix |
| --- | --- | --- |
| `structure` | Missing `sentinelflow.tool.yaml`, invalid YAML, or unknown fields | Start from `plugins/examples/example-echo/sentinelflow.tool.yaml`. |
| `semantic` | High/critical risk without `requiresApproval: true`; bad Schema path | Use repository-relative paths under the plugin root. |
| `compatibility` | Unsupported adapter/mode combination | Use `process` for Command/HTTP/File Import and `container` for Docker. |
| `dependencies` | Missing runner, parser docs, examples, or Schemas | Restore required plugin directories and files. |
| `safety` | Symlink, hidden unsafe path, or install name issue | Use real directories and a safe `metadata.name`. |

## Permission Or Policy Denied

Symptoms:

- CLI exits with code `4`.
- API returns `AuthorizationDenied`.
- `task run` persists `approvalRequired`.

Useful commands:

```sh
target/debug/sentinelflow policy explain tests/fixtures/task.single-step.yaml
target/debug/sentinelflow audit list
```

Fixes:

- Ensure `spec.policy.allowedTargets` contains each target name.
- Ensure `spec.authorizationScope` matches the fixture scope.
- For high or critical risk, create an approval and add
  `spec.policy.approvalRef`.
- For Web/API, use an `operator` token for mutation and an `approver` token for
  approval decisions.

## Parser Fails

Symptoms:

- CLI exits with code `3`.
- Audit contains `result.normalized` with `failed`.
- Result artifact contains a `ParserInputInvalid` or output validation error.

Safe reproduction:

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-invalid-parser
target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/p5_5/task.parser-invalid-output.yaml
```

Fixes:

- Ensure the runner writes JSON matching the plugin output Schema.
- Ensure the Manifest selects the intended trusted built-in parser.
- Keep parser output in the strict envelope: `values`, `findings`, and `errors`.

## Task Timeout

Symptoms:

- Task or run status is `timedOut` or `failed`.
- Audit includes `tool.run.failed`.

Safe reproduction:

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-slow
target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/task.slow.yaml
```

Fixes:

- Increase `spec.policy.timeoutSeconds` only within the safe pilot limits.
- Keep plugin `runtime.timeoutSeconds` bounded.
- Do not remove timeout enforcement to make a test pass.

## Report Generation Fails

Symptoms:

- API returns `SystemError` or `RuntimeError`.
- Audit contains `api.reports.generate` with `failed`.
- No `.sentinelflow/reports/<id>.md` file appears.

Checks:

```sh
target/debug/sentinelflow --workspace .sentinelflow task status <TASK_ID>
target/debug/sentinelflow --workspace .sentinelflow task logs <TASK_ID>
target/debug/sentinelflow --workspace .sentinelflow report generate --task <TASK_ID>
target/debug/sentinelflow --workspace .sentinelflow audit list
```

Fixes:

- Generate reports only for existing task IDs or run IDs.
- Verify `.sentinelflow/reports/` is writable.
- Keep report Finding counts below the v1.0-rc default guard of 5,000.

## Web Cannot See Logs

Symptoms:

- Task completed but the Console log panel is empty.
- SSE stream reconnects repeatedly.

Checks:

```sh
target/debug/sentinelflow --workspace .sentinelflow task logs <TASK_ID>
curl -H 'Authorization: Bearer viewer-token' \
  'http://127.0.0.1:8080/api/tasks/<TASK_ID>/logs?limit=200'
```

Fixes:

- Copy the exact `taskId` returned by task run into the Console Task ID field.
- Use `viewer-token`, `operator-token`, or another role with viewer access.
- Confirm the API is using the same workspace via `SENTINELFLOW_WORKSPACE_DIR`.
- For SSE, reconnect with the last cursor or click Stream Logs again.

## Database Or Migration Errors

Symptoms:

- API health works but resource routes return `SystemError`.
- Store open fails with an unsupported schema version.

Fixes:

- Back up `.sentinelflow/state.db` and artifacts before upgrades.
- Run `cargo test -p sentinelflow-store`.
- See [Upgrade and Migration](deployment/upgrade-and-migration.md).
