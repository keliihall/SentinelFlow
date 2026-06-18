# cmdb-sync-plus

`cmdb-sync-plus` provides bounded CMDB import and controlled writeback
reconciliation.

## Capabilities

- Import JSON and CSV asset inventories.
- Configurable field mapping for heterogeneous CMDB schemas.
- Normalize department, business system, owner, criticality, lifecycle status,
  addresses, and external identifiers.
- Match SentinelFlow assets by external id, name, or address.
- Generate deterministic create, update, no-op, skip, and manual-review
  operations.
- Enforce field allowlists, conflict policies, idempotency keys, and
  optimistic preconditions.

## Writeback boundary

The plugin produces a schema-validated writeback batch but never directly
contacts or mutates a CMDB. Operations with `requires_gateway_write=true` must
be applied by a separately approved CMDB gateway so credentials, network
policy, approval, retries, and audit remain centralized. Deletes are not
supported.

Input files must remain below the plugin root and are limited to 4 MiB.

## Acceptance

```bash
cargo build -p sentinelflow-cli
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/cmdb-sync-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/cmdb-sync-plus
target/debug/sentinelflow --workspace .sentinelflow tool run cmdb-sync-plus \
  --input plugins/official/cmdb-sync-plus/examples/input.writeback-plan.json \
  --authorization-scope fixture:local-only \
  --target enterprise-cmdb-fixture
python3 -m unittest discover -s plugins/official/cmdb-sync-plus/tests -v
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```
