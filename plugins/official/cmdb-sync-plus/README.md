# cmdb-sync-plus

`cmdb-sync-plus` imports CMDB JSON/CSV inventories, normalizes asset ownership,
business-system mapping, responsible owner, lifecycle status, and criticality,
then reconciles them with normalized SentinelFlow assets.

Writeback mode emits deterministic create/update/no-op/manual-review operations
with idempotency keys and preconditions. The plugin does not contact a CMDB or
apply changes itself; an approved CMDB gateway must consume the validated
operation batch. Delete operations are never generated.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/cmdb-sync-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/cmdb-sync-plus
target/debug/sentinelflow --workspace .sentinelflow tool run cmdb-sync-plus \
  --input plugins/official/cmdb-sync-plus/examples/input.writeback-plan.json \
  --authorization-scope fixture:local-only \
  --target enterprise-cmdb-fixture
python3 -m unittest discover -s plugins/official/cmdb-sync-plus/tests -v
```
