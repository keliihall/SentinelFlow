# DAG Orchestration and Policy

## Task DAG

Steps declare unique `name`, `toolRef`, `capability`, `dependsOn`, `inputFrom`,
optional `outputAs`, and `failurePolicy`. Input mappings select values from a
dependency's normalized `ToolOutput` with an absolute JSON Pointer:

```yaml
inputFrom:
  - from: discovery
    pointer: /spec/findings
    target: findings
```

The Planner rejects duplicate names or aliases, missing dependencies, undeclared
mapping sources, cycles, and nodes unreachable from a DAG root. `task plan`
returns deterministic topological order and concurrent levels without executing.

## Scheduler

The Scheduler persists one state per `target/step`, maintains a ready queue, and
starts up to `maxConcurrency` nodes while respecting `rateLimitPerMinute`.

- `stop`: pending work is skipped after failure.
- `continue`: independent nodes continue; blocked dependents are skipped.
- `skipDependents`: transitive dependents are skipped.

Every node still uses Policy, Audit, Adapter, Parser, Schema validation, and the
Normalizer. `inputFrom` never consumes raw stdout.

## Policy

Scopes use `namespace:permission`. Targets may be exact names or typed patterns:
`domain:*.example.com`, `url:https://api.example.com/v1/*`, `ip:192.0.2.10`,
or `cidr:198.51.100.0/24`.

UTC windows use `HH:MM`; `23:00` to `02:00` crosses midnight. Policy also
enforces risk approval, concurrency, rate, timeout, and output retention.
`retainEvidence: false` strips evidence before persistence; `days: 0` purges
normalized results after task completion.

`sentinelflow policy explain task.yaml` emits a decision for every target/step.

## Approvals

```sh
sentinelflow approval request --resource TASK_NAME --risk high
sentinelflow approval approve APPROVAL_ID
sentinelflow approval reject APPROVAL_ID
sentinelflow approval expire APPROVAL_ID
```

Only pending records may transition. `policy.approvalRef` must identify an
approved record bound to the Task name.

## State and Snapshots

Task states are `pending`, `planning`, `approvalRequired`, `running`, `paused`,
`cancelling`, `cancelled`, `failed`, and `completed`. Invalid transitions are
rejected. Each persisted state change emits a `task.state.*` audit event using
the stable names `pending`, `planning`, `approval_required`, `running`,
`paused`, `cancelling`, `cancelled`, `failed`, and `completed`. Blocked or failed
tasks persist `lastError` with a standard error code. Artifacts persist immutable
Task Spec and Plan snapshots, node states, and output run mappings. Resume never
re-reads the source YAML:

```sh
sentinelflow task pause TASK_ID
sentinelflow task cancel TASK_ID
sentinelflow task resume TASK_ID
```
