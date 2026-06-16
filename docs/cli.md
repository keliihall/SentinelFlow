# SentinelFlow CLI

## Scope

The `sentinelflow` CLI provides command discovery, local workspace initialization,
effective configuration inspection, protocol validation, controlled example
execution, normalized result persistence, audit queries, and Markdown reports.

## Implemented Commands

```text
sentinelflow init
sentinelflow config show
sentinelflow tool validate <FILE>
sentinelflow task validate <FILE>
sentinelflow task plan <FILE>
sentinelflow plugin scaffold <PATH>
sentinelflow plugin test <PATH>
sentinelflow plugin validate <PATH>
sentinelflow plugin install <PATH>
sentinelflow tool list
sentinelflow tool info <TOOL>
sentinelflow tool run <TOOL> --input <FILE> --authorization-scope <SCOPE>
sentinelflow task run <TASK.yaml>
sentinelflow task status <TASK_ID>
sentinelflow task logs <TASK_ID>
sentinelflow task pause <TASK_ID>
sentinelflow task cancel <TASK_ID>
sentinelflow task resume <TASK_ID>
sentinelflow policy explain <FILE>
sentinelflow approval request --resource <REF> --risk low|medium|high|critical
sentinelflow approval approve <APPROVAL_ID>
sentinelflow approval reject <APPROVAL_ID>
sentinelflow approval expire <APPROVAL_ID>
sentinelflow report generate --run <RUN_ID>
sentinelflow report generate --task <TASK_ID>
sentinelflow audit list
sentinelflow result export [--run <RUN_ID>] --format json|jsonl|md
```

`plugin scaffold` creates a local-only Python SDK echo fixture. `plugin test`
validates it and runs its example through a temporary workspace. `tool run`
dispatches `command`, `docker`, `http`, and `fileImport` Manifests while retaining
the same Policy, Audit, Parser, and Normalizer pipeline.

`task plan` previews a deterministic DAG. `task run` executes ready nodes within
Policy concurrency and rate limits. Pause, cancel, and resume use persisted Task
Spec and Plan snapshots.

`tool validate` accepts a `sentinelflow.io/v1alpha1` Tool Manifest. `task validate`
accepts a `sentinelflow.io/v1alpha1` Task Spec. Both commands perform Rust structural
decoding and semantic validation without executing anything.

`plugin validate` evaluates structure, semantics, compatibility, dependencies, and
safety. `plugin install` performs a validated, idempotent local installation.
`tool list` and `tool info` query the validated local Tool Registry.

`tool run` executes the registered runner through Policy and the controlled Command
Adapter. `--approve-high-risk` is required for high or critical risk capabilities.
`--timeout-seconds` may lower the Manifest timeout but cannot exceed it. Ctrl-C
requests cancellation and process-group termination.

For the allowlisted low-risk repository examples, `tool run` defaults
`authorizationScope` to `fixture:local-only`; callers may still provide an explicit
scope. Task Specs must always declare their scope.

`task run` accepts YAML or JSON, validates the Task Spec, checks every target against
`policy.allowedTargets`, queries the Tool Registry, and executes the single step once
per target. Target runs share one generated task ID. `task status` prints persisted
task state; `task logs` prints task-correlated Audit Events.

Successful `tool run` output contains the generated execution identifiers and a
normalized `ToolOutput`. Run metadata, normalized results, audit events, and SQLite
indexes are written beneath the selected workspace. Raw stdout and stderr are not
persisted.

`report generate` writes `<workspace>/reports/<run_id>.md`. `result export` writes
normalized data to stdout; without `--run`, it selects the most recently indexed run.
`audit list` emits one `AuditEvent` JSON object per line.

The following command paths exist for interface stability and return a
`NotImplemented` standard error:

```text
sentinelflow task plan
sentinelflow result normalize
```

## Workspace

By default, `sentinelflow init` creates the directories and configuration below.
The first persisted operation additionally creates `state.db`:

```text
.sentinelflow/
  config.yaml
  plugins/
  tools/
  tasks/
  runs/
  results/
  reports/
  audit/
  state.db
```

Initialization is idempotent. Missing directories are restored, but an existing
`config.yaml` is never overwritten. Use `--workspace <PATH>` to select another local
workspace.

## Configuration

Configuration is merged in this order, with later layers taking precedence:

1. Built-in defaults
2. Project configuration at `<workspace>/config.yaml`
3. `SENTINELFLOW_*` environment variables
4. Global CLI options

| Configuration field | Environment variable | CLI option |
| --- | --- | --- |
| `workspaceDir` | `SENTINELFLOW_WORKSPACE_DIR` | `--workspace` |
| `schemaRoot` | `SENTINELFLOW_SCHEMA_ROOT` | `--schema-root` |
| `logLevel` | `SENTINELFLOW_LOG_LEVEL` | `--log-level` |
| `apiEndpoint` | `SENTINELFLOW_API_ENDPOINT` | `--api-endpoint` |
| `authToken` | `SENTINELFLOW_AUTH_TOKEN` | `--auth-token` |

`config show` prints the effective YAML configuration. `authToken` is always rendered
as `********` when set. The API endpoint and token are configuration placeholders;
P1.5 does not implement an API client or service.

Relative `schemaRoot` values are resolved against the process working directory.

## Errors and Exit Codes

Command failures are written to standard error as a
`sentinelflow.io/v1alpha1` `StandardError` resource.

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `2` | Invalid command-line arguments |
| `3` | Schema or semantic validation error |
| `4` | Authorization or policy error |
| `5` | Runtime or not-implemented command error |
| `6` | Configuration, filesystem, or system error |

Validation errors include a JSON-compatible field path whenever available, such as
`$.spec.capabilities[0].requiresApproval`.
