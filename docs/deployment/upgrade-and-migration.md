# SentinelFlow Upgrade And Migration

SentinelFlow v1.0-rc stores durable state under one workspace directory. The
active database is SQLite plus JSON/Markdown artifacts.

## What Must Be Preserved

Back up the complete workspace before upgrading:

| Path | Contents |
| --- | --- |
| `state.db` | SQLite query index and migration metadata |
| `plugins/` | Installed plugin packages |
| `tasks/` | Task artifacts and plan snapshots |
| `runs/` | Run metadata |
| `results/` | Normalized outputs and standard errors |
| `reports/` | Markdown reports |
| `audit/` | Append-only audit JSONL |
| `approvals/` | Approval records |
| `logs/` | Operator/service logs |

## Backup

```sh
export SF_WORKSPACE=/srv/sentinelflow/.sentinelflow
sqlite3 "$SF_WORKSPACE/state.db" ".backup '$SF_WORKSPACE/state.db.backup'"
tar -C "$SF_WORKSPACE" -czf "$SF_WORKSPACE/artifacts.backup.tgz" \
  plugins tasks runs results reports audit approvals logs
```

## Upgrade

1. Stop the API service.
2. Take the backup above.
3. Deploy the new `sentinelflow-api` and `sentinelflow` binaries or rebuild the
   container image.
4. Start the API service.
5. The first store access runs idempotent SQLite migrations.
6. Verify health and run a safe `example-echo` task.

## Migration Semantics

- Initial migration creates all required tables and records the current schema
  version in `schema_migrations`; v1.0-rc currently records version `3`.
- Schema version `3` adds bounded audit/task-log query fields and indexes used
  by the P5.5 performance baseline.
- Incremental migrations add missing columns and preserve existing rows.
- Re-running migrations is idempotent.
- A database from a newer unsupported schema version fails explicitly and does
  not silently downgrade.
- Migration errors surface as `SystemError`; they do not bypass Policy, Audit,
  Parser, Normalizer, or Report boundaries.

## Rollback

1. Stop the API service.
2. Restore the prior binaries or container image.
3. Restore `state.db` and artifacts from backup.
4. Start the API service.
5. Verify `/health`, task list, audit list, and one safe `example-echo` run.

## Validation

Run:

```sh
cargo test -p sentinelflow-store
tests/e2e/p5_5_deployment/run.sh
```

The P5.5 deployment test creates a previous-version workspace fixture, opens it
with the current store, verifies migration version metadata, and confirms tools,
tasks, runs, findings, audit, and reports are preserved.
