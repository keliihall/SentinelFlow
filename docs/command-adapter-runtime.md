# Command Adapter and Controlled Runtime

## Scope

The runtime executes only validated allowlisted repository plugins through the
Command Adapter. It does not provide arbitrary command execution, shell
execution, scanning, exploitation, credential testing, persistence, or network
automation.

## Adapter Lifecycle

All adapters implement the asynchronous `Adapter` trait:

```text
prepare -> execute -> collect
                  \-> cancel
```

- `prepare` performs Policy, identity, input Schema, path, and configuration checks.
- `execute` starts the declared runner without a shell.
- `collect` waits, enforces limits, parses JSON, validates the runner output Schema,
  and returns an in-memory `ExecutionResult` for the Parser stage.
- `cancel` signals the active run and causes its process group to be terminated.

The Command Adapter calls Policy inside `prepare`; callers cannot use the Adapter
lifecycle while skipping Policy.

## Execution Request

Every request carries generated identifiers:

- `taskId`
- `runId`
- `stepId`
- `toolId`
- `correlationId`

It also carries the validated plugin root and Manifest, selected capability, JSON
input, authorization scope, explicit high-risk approval state, and requested timeout.

## Manifest Runtime Declaration

`ToolManifest.spec.runtime` supports:

| Field | Purpose |
| --- | --- |
| `mode` | Must be `process` for the Command Adapter |
| `entrypoint` | Relative executable path beneath `runner/` |
| `args` | Fixed argument array passed directly to the executable |
| `environmentAllowlist` | Host variable names that may be inherited |
| `timeoutSeconds` | Plugin timeout ceiling, from 1 through 3600 |
| `outputLimitBytes` | Combined stdout/stderr limit, up to 16 MiB |

No field accepts a shell command string. Argument values are passed unchanged to the
operating system process API. Entrypoints, input Schemas, and output Schemas are
canonicalized and must remain within the plugin root.

## Process Controls

The Command Adapter:

- Uses an executable plus argument array, never `sh -c` or equivalent.
- Creates a fresh temporary working directory for every run and removes it afterward.
- Clears the child environment, inherits only Manifest-allowlisted values, and adds
  SentinelFlow correlation identifiers.
- Pipes JSON input over stdin.
- Reads stdout and stderr concurrently.
- Counts stdout and stderr against one bounded output limit.
- Does not retain stderr or place raw output in `ExecutionResult`.
- Terminates the Unix process group on timeout, cancellation, or output limit.
- Parses stdout as JSON and validates it against the declared output Schema.

Only validated JSON output is returned to the trusted Parser. The Normalizer performs
a second protocol validation before any result is persisted.

## Policy

The minimum P2-2 policy is default deny:

- Only explicitly allowlisted repository tools may execute.
- Missing or blank `authorizationScope` is denied.
- High and critical risk capabilities require explicit approval.
- A zero timeout is denied.
- A requested timeout above the Manifest ceiling is denied.
- A running process that reaches its accepted timeout is terminated.

Policy denials use CLI exit code `4`. Schema failures use `3`; controlled runtime
failures use `5`; system failures use `6`.

## Audit

Run lifecycle events are `tool.run.requested`, `policy.denied`, `tool.run.started`,
`tool.run.finished`, `tool.run.failed`, and `result.normalized`. Each event carries
task, run, step, tool, actor, and correlation identifiers. Events contain no input,
stdout, stderr, credentials, or raw plugin output.

## Cancellation

The Adapter API supports programmatic cancellation by `runId`. The CLI maps Ctrl-C
to `cancel`, waits for process-group termination, and returns a controlled runtime
error.

## Safe Example

`example-echo` is the acceptance example plugin. Its runner:

- Reads one JSON object from stdin.
- Requires a bounded string `message`.
- Returns the same string as JSON.
- Accepts no target, network, credential, or shell command input.
