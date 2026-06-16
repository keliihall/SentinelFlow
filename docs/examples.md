# SentinelFlow Safe Examples

All examples in this document are local, synthetic, and safe. They do not scan,
probe, exploit, brute force, bypass authentication, persist access, use real
credentials, or contact external targets.

Build once before running examples:

```sh
cargo build --workspace
target/debug/sentinelflow --workspace .sentinelflow init
```

## example-echo

Purpose: prove the Command Adapter, trusted parser, Normalizer, Store, Report,
and Audit loop with one bounded message.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow tool run example-echo \
  --input plugins/examples/example-echo/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-one
```

## example-file-import

Purpose: prove File Import Adapter behavior with bounded synthetic JSON records
supplied over stdin. The example does not open caller-selected host files.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-file-import
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-file-import
target/debug/sentinelflow --workspace .sentinelflow tool run example-file-import \
  --input plugins/examples/example-file-import/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-import
```

## restricted-risk-mock

Purpose: prove high-risk approval flow without implementing high-risk behavior.
The plugin performs local echo only, but declares `risk: high` and
`requiresApproval: true`.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-restricted-high-risk
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-restricted-high-risk
target/debug/sentinelflow --workspace .sentinelflow policy explain tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml
target/debug/sentinelflow --workspace .sentinelflow task run tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml || true
```

The final command is expected to stop in a controlled approval-required state.
Create and approve an approval record:

```sh
APPROVAL_ID="$(
  target/debug/sentinelflow --workspace .sentinelflow approval request \
    --resource p55-full-restricted-high-risk \
    --risk high \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["approvalId"])'
)"
export APPROVAL_ID
target/debug/sentinelflow --workspace .sentinelflow approval approve "$APPROVAL_ID"
```

Copy the fixture to a temporary file and add `spec.policy.approvalRef`:

```sh
python3 - <<'PY'
import os
from pathlib import Path
src = Path("tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml")
dst = Path("/tmp/sentinelflow-approved-task.yaml")
approval_id = os.environ["APPROVAL_ID"]
text = src.read_text(encoding="utf-8")
text = text.replace("    approveHighRisk: false", f"    approveHighRisk: false\n    approvalRef: {approval_id}")
dst.write_text(text, encoding="utf-8")
print(dst)
PY
target/debug/sentinelflow --workspace .sentinelflow task run /tmp/sentinelflow-approved-task.yaml
```

## single-step task

Purpose: run `example-echo` across two safe targets.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow task validate tests/fixtures/task.single-step.yaml
target/debug/sentinelflow --workspace .sentinelflow task plan tests/fixtures/task.single-step.yaml
TASK_ID="$(
  target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/task.single-step.yaml \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["taskId"])'
)"
target/debug/sentinelflow --workspace .sentinelflow report generate --task "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow audit list
```

## approval-required task

Purpose: demonstrate default-deny approval behavior. Use
`tests/fixtures/p5_5/task.high-risk-unapproved.yaml` with
`plugins/examples/example-high-risk`.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-high-risk
target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/p5_5/task.high-risk-unapproved.yaml || true
```

The controlled result should indicate approval is required. Do not bypass this
check to make tests pass.

## partial-failure task

Purpose: prove DAG failure policy and partial result handling with one fixed
failure plugin and one independent safe echo step.

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-failure
target/debug/sentinelflow --workspace .sentinelflow task validate tests/fixtures/p5_5/task.partial-failure.yaml
target/debug/sentinelflow --workspace .sentinelflow task plan tests/fixtures/p5_5/task.partial-failure.yaml
target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/p5_5/task.partial-failure.yaml || true
```

The task may finish with controlled failure state while preserving successful
independent outputs, errors, audit events, and reportability.
