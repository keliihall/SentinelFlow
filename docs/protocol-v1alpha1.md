# SentinelFlow Protocol v1alpha1

## Scope

Protocol version `sentinelflow.io/v1alpha1` defines the minimum portable resource
contracts for SentinelFlow. It contains no network behavior, API service, scanning,
or attack logic.

## Resource Envelope

Every top-level resource contains:

| Field | Meaning |
| --- | --- |
| `apiVersion` | Must be `sentinelflow.io/v1alpha1` |
| `kind` | Must match the concrete resource type |
| `metadata` | Common name, namespace, UID, labels, and annotations |
| `extensions` | Namespaced forward-compatible extension values |
| `spec` or `error` | Resource-specific payload |

Unknown fields are rejected. `extensions` is the only supported location for
forward-compatible fields.

`spec.runtime.adapter` selects `command`, `docker`, `http`, or `fileImport`.
Command, HTTP, and File Import require process mode; Docker requires container
mode. Sensitive HTTP headers must use `secretRef`, and Docker mount sources must
remain under the plugin's `examples/` directory.

Normalized Findings carry a tool-scoped `fingerprint`, a
`crossToolFingerprint`, and an optional persisted `duplicateOf` reference.

## DAG Tasks

Task steps support `dependsOn`, `inputFrom`, `outputAs`, and `failurePolicy`.
Input pointers are evaluated only against a prior normalized `ToolOutput`.
Task Policy supports exact targets, domain/URL/IP/CIDR patterns, approval
references, cross-midnight UTC windows, concurrency, rate limits, timeout, and
output retention.

## Resources

- `ToolManifest`: tool identity, capabilities, runtime, trusted parser selection,
  and input/output Schema paths.
- `Capability`: name, description, risk level, and approval requirement.
- `ToolInput`: schema reference and structured input values.
- `ToolOutput`: schema reference, normalized values, findings, and standard errors.
- `Finding`: normalized title, severity, summary, and evidence.
- `Evidence`: typed, structured, non-sensitive supporting information.
- `StandardError`: stable code, message, optional field path, and structured details.
- `AuditEvent`: action, outcome, timestamp, resource, and execution correlation IDs.
- `TaskSpec`: single-step task with mandatory `authorizationScope`, named targets,
  one tool step, and task-local policy.
- `Policy`: default-deny draft policy with scoped rules.

`metadata.schema.json` defines the reusable Common Metadata object.

## Copyable Resource Examples

### Tool Manifest

`plugins/examples/example-echo/sentinelflow.tool.yaml`:

```yaml
apiVersion: sentinelflow.io/v1alpha1
kind: ToolManifest
metadata:
  name: example-echo
  labels:
    sentinelflow.io/example: "true"
spec:
  displayName: Example Echo
  version: 0.1.0
  capabilities:
    - name: echo
      description: Returns a caller-provided synthetic message without network access
      risk: low
      requiresApproval: false
  runtime:
    mode: process
    entrypoint: runner/echo.py
    args: []
    environmentAllowlist:
      - PATH
    timeoutSeconds: 5
    outputLimitBytes: 65536
  parser:
    mode: builtin
    name: example-echo-v1
  inputSchema: schemas/input.schema.json
  outputSchema: schemas/output.schema.json
extensions:
  sentinelflow.io/safetyProfile: local-echo-only
```

Validate it with:

```sh
target/debug/sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow tool validate tests/fixtures/v1alpha1/valid-tool-manifest.json
```

### Task Spec

`tests/fixtures/task.single-step.yaml`:

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
        message: hello from task target one
    - name: fixture-two
      input:
        message: hello from task target two
  steps:
    - name: echo
      toolRef: example-echo
      capability: echo
      failurePolicy: stop
  policy:
    allowedTargets:
      - fixture-one
      - fixture-two
    approveHighRisk: false
    timeoutSeconds: 5
    maxConcurrency: 1
    rateLimitPerMinute: 60
    outputRetention:
      days: 30
      retainEvidence: true
extensions: {}
```

Validate and plan it with:

```sh
target/debug/sentinelflow task validate tests/fixtures/task.single-step.yaml
target/debug/sentinelflow task plan tests/fixtures/task.single-step.yaml
target/debug/sentinelflow policy explain tests/fixtures/task.single-step.yaml
```

### Finding

`tests/fixtures/v1alpha1/valid-finding.json` is a standalone normalized Finding:

```json
{
  "apiVersion": "sentinelflow.io/v1alpha1",
  "kind": "Finding",
  "metadata": {"name": "synthetic-configuration-observation"},
  "spec": {
    "title": "Synthetic configuration observation",
    "severity": "info",
    "summary": "A fixture-only observation used to validate protocol handling.",
    "evidence": [
      {
        "evidenceType": "structured",
        "description": "Synthetic and non-sensitive fixture evidence",
        "data": {"source": "fixture"}
      }
    ]
  },
  "extensions": {}
}
```

Persisted Findings generated by tool execution additionally receive stable
`fingerprint`, `crossToolFingerprint`, and optional `duplicateOf`.

### Evidence

Evidence is always structured and non-sensitive:

```json
{
  "evidenceType": "synthetic-message",
  "description": "Structured output emitted by the local example runner.",
  "data": {"message": "hello from a synthetic fixture"}
}
```

### Standard Error

Failures are represented as `StandardError` resources or embedded error details:

```json
{
  "apiVersion": "sentinelflow.io/v1alpha1",
  "kind": "StandardError",
  "metadata": {"name": "cli-error"},
  "error": {
    "code": "PolicyDenied",
    "message": "target is outside the authorization boundary",
    "field": "$.spec.policy.allowedTargets"
  }
}
```

CLI exit codes are stable: `2` argument, `3` Schema, `4` authorization/policy,
`5` runtime, and `6` system.

### Audit Event

Audit Events are append-only records under `.sentinelflow/audit/events.jsonl` and
indexed in SQLite:

```json
{
  "apiVersion": "sentinelflow.io/v1alpha1",
  "kind": "AuditEvent",
  "metadata": {"name": "audit-tool-run-finished-example"},
  "spec": {
    "action": "tool.run.finished",
    "outcome": "succeeded",
    "actor": "local-cli",
    "timestamp": "2026-06-15T00:00:00Z",
    "resourceRef": "run-example",
    "taskId": "task-example",
    "runId": "run-example",
    "stepId": "step-example",
    "toolId": "example-echo",
    "actorId": "local-cli",
    "correlationId": "corr-example"
  },
  "extensions": {}
}
```

### Policy

Task-local policy is the active v1.0-rc policy surface:

```yaml
policy:
  allowedTargets:
    - fixture-one
  targetPatterns: []
  approveHighRisk: false
  approvalRef: run-approval-id
  timeoutSeconds: 30
  maxConcurrency: 1
  rateLimitPerMinute: 60
  timeWindows: []
  outputRetention:
    days: 30
    retainEvidence: true
```

`approvalRef` is optional and must refer to an approved record whose
`resourceRef` equals the Task Spec `metadata.name`.

## Validation

Validation has two layers:

1. Structural validation uses the checked-in JSON Schema and Rust `serde` types.
   It verifies required fields, `apiVersion`, `kind`, runtime `mode`, enum values,
   unknown fields, and basic length constraints.
2. Semantic validation uses the Rust `Validate` trait. It verifies non-empty semantic
   identifiers, high/critical capability approval, repository-relative resolvable
   input/output Schema paths, mandatory task authorization scope, and default-deny
   policy behavior.

Failures carry JSON-compatible paths such as
`$.spec.capabilities[0].requiresApproval`. Structural errors for a missing property
identify its containing object and name the missing field.

P2-4 `TaskSpec.spec` contains:

- `authorizationScope`
- one or more `targets`, each with a name and exact structured tool input
- exactly one entry in `steps`, declaring name, `toolRef`, and capability
- `policy.allowedTargets`, `approveHighRisk`, and optional `timeoutSeconds`

Target membership in `allowedTargets` is evaluated by Policy during `task run`, not
by structural Schema validation.

Schema paths must be repository-relative, must not contain parent traversal, and
must resolve beneath the validation context root.

The optional Command Adapter declaration under `ToolManifest.spec.runtime` includes
`entrypoint`, fixed `args`, `environmentAllowlist`, `timeoutSeconds`, and
`outputLimitBytes`. Entrypoints must be relative paths beneath `runner/`.
`SENTINELFLOW_*` environment names are reserved and cannot be inherited from the
host.

`ToolManifest.spec.parser` selects a trusted parser by `mode` and stable `name`.
P2-3 supports only `builtin` parsers. Parser output is decoded into a strict envelope,
converted to `ToolOutput`, `Finding`, `Evidence`, and `StandardError`, then validated
again before persistence.

## Schema Maintenance

Rust types are authoritative. Regenerate checked-in schemas with:

```text
cargo run -p sentinelflow-schema --example generate_schemas
```

Contract tests fail when generated schemas differ from files under
`schemas/v1alpha1/`.

## Safety Boundary

Capabilities are declarations, not implementations. High and critical declarations
must set `requiresApproval: true`. A `runtime.mode` value describes an isolation
requirement but does not start a process. All examples and fixtures are synthetic.
