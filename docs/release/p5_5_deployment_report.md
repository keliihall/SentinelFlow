# SentinelFlow P5.5 Deployment Report

Generated: 2026-06-17T01:47:37Z

Command: `tests/e2e/p5_5_deployment/run.sh`
Clean workspace: `/var/folders/46/j153v48s4dqg3wg85sg3g4mw0000gn/T/sentinelflow-p55-deployment.6gq872yw/clean/.sentinelflow`
Upgrade fixture workspace: `/var/folders/46/j153v48s4dqg3wg85sg3g4mw0000gn/T/sentinelflow-p55-deployment.6gq872yw/upgrade/.sentinelflow`

## Scope

This report covers single-node deployment readiness, clean API/Web startup, safe example-echo execution, SQLite schema migration idempotency, previous-version upgrade preservation, and documented backup/restore paths.

No real targets, credentials, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.

## Result Summary

| Category | Expected Deployment Behavior | Result | Evidence |
| --- | --- | --- | --- |
| Compose 配置 | Docker Compose 配置可解析 | pass | docker compose config passed |
| 干净环境启动 | API Service 和 Web Console 可访问 | pass | console=200 |
| example-echo 闭环 | 部署后可安装 example-echo、执行任务并生成报告 | pass | run=200 report=200 task=task-4c52ffa3-c533-4549-93d5-6e364f939a4b |
| 安全默认配置 | 高风险执行默认仍需审批 | pass | fixtures default to low risk; policy gate tested in release suites |
| SQLite 初始化迁移 | 干净 workspace 初始化 schema_migrations | pass | version=3 |
| 挂载目录 | plugins/reports/logs 目录存在 | pass | plugins/reports/logs present |
| 上一版本升级 | 旧 schema fixture 升级后保留核心数据 | pass | audit=200 version=3 counts={'tools': 1, 'tasks': 1, 'runs': 1, 'findings': 1, 'audit_events': 1} report=True audit=True |
| 迁移幂等 | 重复启动不改变 schema version 且不破坏数据 | pass | before=3 after=3 |

## Deployment Matrix

| Area | Status |
| --- | --- |
| API Service | Covered by clean startup and `/health` check. |
| Web Console | Served from the API container at `/console`. |
| SQLite | Active v1.0-rc backend with `schema_migrations` version metadata. |
| PostgreSQL | Documented as reserved/not active in v1.0-rc to avoid silent fallback. |
| Plugin directory | Mounted separately by Compose and backed up explicitly. |
| Report directory | Mounted separately by Compose and backed up explicitly. |
| Log directory | Created in workspace and mounted separately by Compose. |

## Release Decision

- Failed checks: `0`
- Result: `pass`
