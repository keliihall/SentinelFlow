# Single-Step Task MVP

> Superseded by the P4 DAG implementation in
> `docs/dag-orchestration-and-policy.md`. A single-step Task remains valid as a
> one-node DAG.

## Scope

P2-4 supports one Task Spec, exactly one tool step, and one or more synthetic targets.
It does not implement multi-step orchestration, dependencies between steps, retries,
parallel execution, scheduling, or attack chains.

## Task Spec

```yaml
apiVersion: sentinelflow.io/v1alpha1
kind: TaskSpec
metadata:
  name: example-single-step
spec:
  authorizationScope: fixture:local-only
  targets:
    - name: fixture-one
      input:
        message: hello
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
  policy:
    allowedTargets:
      - fixture-one
    approveHighRisk: false
    timeoutSeconds: 5
extensions: {}
```

Each target contains the exact structured input validated by the selected tool's
input Schema. The target name must be explicitly present in `allowedTargets`.

## Execution

`task run` performs Schema and semantic validation, task-local Policy evaluation,
Tool Registry lookup, Command Adapter execution, Parser invocation, normalization,
storage, and audit recording. Each target receives its own run ID while all runs
share the generated task ID.

```text
sentinelflow task run tests/fixtures/task.single-step.yaml
sentinelflow task status <task_id>
sentinelflow task logs <task_id>
sentinelflow report generate --task <task_id>
```

Task state is stored in `.sentinelflow/tasks/<task_id>.json`. Reports aggregate all
target runs. A failure marks the task terminally failed or cancelled and preserves
the standard error and related Audit Events.
