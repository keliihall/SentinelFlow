# SentinelFlow 中文说明

SentinelFlow 是一个面向外部安全验证工具的管理框架。它提供统一注册、统一接入、受控执行、标准输出、审计、策略控制、报告生成和持续扩展能力。

SentinelFlow 不是扫描器、漏洞利用框架、弱口令爆破工具、攻击平台或攻击链自动化系统。本仓库只包含安全的框架能力、协议、适配器、示例插件和测试 Fixture，不包含真实攻击能力。

## 当前状态

当前代码库处于 `v1.0-rc` 候选准备阶段，重点是产品化加固、验证、测试和试点可用性。

已具备：

- Rust workspace 基线
- `sentinelflow` CLI
- `sentinelflow.io/v1alpha1` 协议与 Schema
- Tool Manifest 校验、插件发现、插件安装
- Command、Docker、HTTP、File Import Adapter
- DAG Task Plan 与 Task Run
- Policy Explain、默认拒绝、高风险审批
- Audit Event、Run/Result/Report 持久化
- Finding/Evidence Normalizer 与去重
- API Service
- Web Console
- Python SDK 示例
- P5.5 smoke、一致性、完整闭环 E2E
- Docker Compose 单机部署路径

仍不包含：

- 插件市场
- 分布式 Worker
- AI 自动分析
- 高级团队空间
- 真实漏洞扫描、漏洞利用、爆破、认证绕过、持久化、隐蔽探测或攻击链能力

## 核心约定

| 项目 | 值 |
| --- | --- |
| 产品名称 | `SentinelFlow` |
| CLI 二进制 | `sentinelflow` |
| 本地工作目录 | `.sentinelflow/` |
| API Group | `sentinelflow.io` |
| 环境变量前缀 | `SENTINELFLOW_` |
| 协议版本 | `sentinelflow.io/v1alpha1` |

## 安全边界

SentinelFlow 的安全模型是默认拒绝：

- Web Console 只能调用 API，不能直接执行工具。
- API 必须复用 Core/CLI 编排路径，不能另起一套工具执行逻辑。
- Adapter 不得绕过 Policy、Audit、Parser 和 Normalizer。
- 所有工具必须通过 Manifest + Adapter + Parser 接入。
- 新增工具不得修改 Core。
- 所有关键动作必须记录 Audit Event。
- 所有输出必须经过 Schema 校验和 Normalizer。
- 插件不得以内联动态库方式加载到 Core 进程。
- 示例插件只能使用本地 synthetic fixture，不得访问真实目标或真实凭据。

禁止能力包括：

- 真实扫描器或漏洞利用实现
- 弱口令或凭据爆破
- 持久化机制
- 隐蔽探测
- 认证或授权绕过
- 自动化攻击链
- 真实目标、真实凭据、真实 secret 或操作性攻击 payload

更多细节见 [Security Boundary](docs/security-boundary.md)。

## 环境要求

最低要求：

- Rust `1.85` 或更高版本
- Python 3，用于安全示例 Command 插件

可选：

- Docker
- Docker Compose

## 快速开始：本地 CLI + API + Web

从干净环境开始，先构建本地二进制并完成 CLI 闭环：

```sh
cargo build --workspace
target/debug/sentinelflow --workspace .sentinelflow init
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow tool run example-echo \
  --input plugins/examples/example-echo/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-one
TASK_ID="$(
  target/debug/sentinelflow --workspace .sentinelflow task run tests/fixtures/task.single-step.yaml \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["taskId"])'
)"
target/debug/sentinelflow --workspace .sentinelflow report generate --task "$TASK_ID"
target/debug/sentinelflow --workspace .sentinelflow audit list
```

然后启动 API 和 Web Console：

```sh
SENTINELFLOW_WORKSPACE_DIR=.sentinelflow \
SENTINELFLOW_SCHEMA_ROOT=. \
target/debug/sentinelflow-api
```

然后打开：

```text
http://127.0.0.1:8080/console
```

本地开发登录：

| 角色 | 用户名 | 密码 | Token |
| --- | --- | --- | --- |
| Viewer | `viewer` | `sentinelflow` | `viewer-token` |
| Operator | `operator` | `sentinelflow` | `operator-token` |
| Approver | `approver` | `sentinelflow` | `approver-token` |
| Admin | `admin` | `sentinelflow` | `admin-token` |

这些凭据只用于本地开发和测试。任何生产或共享试点环境都必须替换身份提供者。

## Web Console 完整试用流程

进入 Console 后按顺序操作：

1. 登录并确认 session。
2. 插件路径填写 `plugins/examples/example-echo`。
3. 执行 Plugin Validate。
4. 执行 Plugin Install。
5. 加载工具列表，确认 `example-echo` 已出现。
6. 使用默认 Task Spec 或填写低风险 Task Spec。
7. 执行 Task Validate。
8. 执行 Task Plan。
9. 执行 Policy Explain，确认所有 decision allowed。
10. 执行 Task Run。
11. 复制返回的 `taskId`。
12. 查看 Task Status。
13. 查看 Task Logs。
14. 连接 Stream Logs。
15. 查看 Findings。
16. 生成 Task Report。
17. 读取 Report。
18. 查看 Audit Events。

详细试用说明见 [v1.0-rc Trial Guide](docs/v1rc-trial-guide.md)。

## CLI 使用

初始化本地工作区：

```sh
cargo run -p sentinelflow-cli -- init
```

或使用构建后的二进制：

```sh
target/debug/sentinelflow init
```

默认工作区结构：

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

常用命令：

```sh
sentinelflow config show
sentinelflow plugin validate plugins/examples/example-echo
sentinelflow plugin install plugins/examples/example-echo
sentinelflow tool list
sentinelflow tool info example-echo
sentinelflow task validate tests/fixtures/task.single-step.yaml
sentinelflow task plan tests/fixtures/task.single-step.yaml
sentinelflow policy explain tests/fixtures/task.single-step.yaml
sentinelflow task run tests/fixtures/task.single-step.yaml
sentinelflow task status <TASK_ID>
sentinelflow task logs <TASK_ID>
sentinelflow report generate --task <TASK_ID>
sentinelflow audit list
```

高风险审批示例：

```sh
sentinelflow plugin install plugins/examples/example-restricted-high-risk
sentinelflow policy explain tests/e2e/p5_5_full_flow/fixtures/scenario_b_restricted_high_risk.yaml
sentinelflow approval request --resource p55-full-restricted-high-risk --risk high
sentinelflow approval approve <APPROVAL_ID>
```

再将 `approvalRef` 写入 Task Spec 后执行任务。

完整 CLI 文档见 [CLI Guide](docs/cli.md)。

## 配置层级

配置按以下顺序合并，后者覆盖前者：

1. 内置默认值
2. `<workspace>/config.yaml`
3. `SENTINELFLOW_*` 环境变量
4. CLI 参数

常用配置：

| 配置字段 | 环境变量 | CLI 参数 |
| --- | --- | --- |
| `workspaceDir` | `SENTINELFLOW_WORKSPACE_DIR` | `--workspace` |
| `schemaRoot` | `SENTINELFLOW_SCHEMA_ROOT` | `--schema-root` |
| `logLevel` | `SENTINELFLOW_LOG_LEVEL` | `--log-level` |
| `apiEndpoint` | `SENTINELFLOW_API_ENDPOINT` | `--api-endpoint` |
| `authToken` | `SENTINELFLOW_AUTH_TOKEN` | `--auth-token` |

`config show` 会展示最终配置，并遮蔽 `authToken`。

## 标准退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `2` | 参数错误 |
| `3` | Schema 或语义校验错误 |
| `4` | 授权或策略错误 |
| `5` | 运行时错误或未实现命令 |
| `6` | 配置、文件系统或系统错误 |

失败会输出 `sentinelflow.io/v1alpha1` `StandardError`。

## 插件与示例

示例插件位于 [plugins/examples](plugins/examples)。

当前安全示例包括：

| 插件 | 用途 |
| --- | --- |
| `example-echo` | 本地 echo，低风险成功路径 |
| `example-dns-resolve` | 使用内置 mock 表，不访问真实 DNS |
| `example-file-import` | 从 stdin 受控导入 JSON/JSONL/CSV |
| `example-failure` | 固定失败，用于失败策略测试 |
| `example-slow` | 延迟输出，用于超时与取消测试 |
| `example-invalid-parser` | 故意触发 Parser/Normalizer 负向路径 |
| `example-restricted-high-risk` | 本地 echo，但声明 high risk，用于审批测试 |
| `example-finding-consumer` | 消费上游 Finding，用于 DAG 映射测试 |
| `example-docker-adapter` | Docker Adapter 安全示例 |
| `example-http-adapter` | HTTP Adapter loopback 安全示例 |
| `example-structured-import` | 结构化导入示例 |

所有示例都必须保持安全 mock 或 fixture 属性。

## Task Spec、Policy 与审批

Task Spec 使用 `sentinelflow.io/v1alpha1`：

- `metadata.name` 定义任务名。
- `spec.authorizationScope` 定义授权范围。
- `spec.targets` 定义明确目标和输入。
- `spec.steps` 定义 DAG 步骤。
- `spec.policy.allowedTargets` 明确允许的目标。
- `spec.policy.timeWindows` 可定义 UTC 时间窗，支持跨午夜。
- `spec.policy.approvalRef` 可绑定审批记录。

执行前会进行：

1. Task Spec Schema 和语义校验
2. DAG Plan 校验
3. Policy Explain
4. 运行时 Policy 检查
5. Adapter 执行
6. Parser
7. Normalizer
8. Store
9. Audit
10. Report

高风险或 critical capability 默认拒绝，必须有审批记录或明确策略允许。

## Adapter

当前 Adapter：

- Command Adapter
- Docker Adapter
- HTTP Adapter
- File Import Adapter

Adapter 只负责受控执行或受控导入，不能绕过：

- Policy
- Audit
- Parser
- Normalizer
- Store

更多说明：

- [Command Adapter Runtime](docs/command-adapter-runtime.md)
- [Adapters and Python SDK](docs/adapters-and-python-sdk.md)

## API Service 与 Web Console

启动 API：

```sh
cargo run -p sentinelflow-api
```

健康检查：

```sh
curl http://127.0.0.1:8080/health
```

OpenAPI：

```text
http://127.0.0.1:8080/openapi.json
```

Console：

```text
http://127.0.0.1:8080/console
```

API/Web 边界：

- Web 只调用 API。
- Web 不执行工具。
- Web 不读取 `.sentinelflow`。
- Web 不复制 Policy 逻辑。
- API 执行任务时复用现有 SentinelFlow 编排路径。

更多说明见 [API Service and Web Console](docs/api-service-and-web-console.md)。

## 结果、审计与报告

执行会产生：

- `RunArtifact`
- `ResultArtifact`
- `AuditEvent`
- normalized `ToolOutput`
- Finding/Evidence
- Markdown Report

默认存储在：

```text
.sentinelflow/
  runs/
  results/
  audit/
  reports/
  state.db
```

报告生成：

```sh
sentinelflow report generate --task <TASK_ID>
```

或通过 Web/API：

```http
POST /api/reports/generate
```

更多说明见 [Results, Audit, and Reports](docs/results-audit-reporting.md)。

## Docker Compose 单机试用

```sh
docker compose up --build
```

然后打开：

```text
http://127.0.0.1:8080/console
```

Compose 会使用 `sentinelflow-workspace`、`sentinelflow-plugins`、
`sentinelflow-reports` 和 `sentinelflow-logs` volume 保存工作区、插件、报告和日志。

当前只支持单机部署形态。

## 测试与发布门禁

推荐发布前执行：

```sh
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
tests/e2e/p5_5_smoke.sh
tests/e2e/p5_5_consistency.sh
tests/e2e/p5_5_full_flow/run.sh
tests/e2e/p5_5_security/run.sh
tests/e2e/p5_5_reliability/run.sh
tests/e2e/p5_5_deployment/run.sh
tests/performance/run.sh
```

说明：

- 部分测试会启动本地 `127.0.0.1` HTTP/SSE 服务。
- 在受限沙箱中，这类测试可能需要允许本地 socket bind。
- 所有 E2E 使用临时工作区，可重复运行。
- 不使用公网目标、真实凭据或真实攻击 payload。

E2E 报告：

- [P5.5 Consistency Report](docs/release/p5_5_consistency_report.md)
- [P5.5 Full E2E Report](docs/release/p5_5_e2e_report.md)
- [P5.5 Security Hardening Report](docs/release/p5_5_security_hardening_report.md)
- [P5.5 Reliability Report](docs/release/p5_5_reliability_report.md)
- [P5.5 Deployment Report](docs/release/p5_5_deployment_report.md)
- [P5.5 Performance Baseline](docs/release/p5_5_performance_baseline.md)

部署文档：

- [Local Demo Deployment](docs/deployment/local-demo.md)
- [Production-like Deployment](docs/deployment/production-like.md)
- [Upgrade and Migration](docs/deployment/upgrade-and-migration.md)

## 目录结构

```text
crates/
  sentinelflow-cli/
  sentinelflow-core/
  sentinelflow-schema/
  sentinelflow-runtime/
  sentinelflow-registry/
  sentinelflow-adapter-command/
  sentinelflow-adapter-docker/
  sentinelflow-adapter-http/
  sentinelflow-adapter-file-import/
  sentinelflow-store/
  sentinelflow-policy/
  sentinelflow-report/
  sentinelflow-orchestrator/
  sentinelflow-api/
schemas/v1alpha1/
plugins/examples/
sdk/python/
docs/
tests/fixtures/
tests/integration/
tests/e2e/
```

## 重要文档

- [Architecture Baseline ADR](docs/adr/0001-architecture-baseline.md)
- [Protocol v1alpha1](docs/protocol-v1alpha1.md)
- [CLI Guide](docs/cli.md)
- [Plugin Registry](docs/plugin-registry.md)
- [Safe Examples](docs/examples.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Command Adapter Runtime](docs/command-adapter-runtime.md)
- [DAG Orchestration and Policy](docs/dag-orchestration-and-policy.md)
- [API Service and Web Console](docs/api-service-and-web-console.md)
- [Security Boundary](docs/security-boundary.md)
- [v1.0-rc Trial Guide](docs/v1rc-trial-guide.md)
- [v1.0-rc Release Notes](docs/release-v1.0-rc.md)
- [v1.0-rc Acceptance Report](docs/v1.0-rc-acceptance-report.md)

## 开发原则

贡献或继续开发时必须遵守：

- 每次只完成当前阶段任务，不提前实现后续阶段大功能。
- 新工具必须通过 Manifest + Adapter + Parser 接入。
- 新工具不得修改 Core。
- Web/API 不能绕过 Core/CLI 编排路径直接执行工具。
- Adapter 不能绕过 Policy、Audit、Normalizer。
- 所有新增用户可见行为必须有文档。
- 所有修复必须有测试覆盖。
- 不得为了测试通过关闭安全校验。
- 不得提交真实目标、真实凭据或攻击 payload。

## 当前发布建议

当前 `v1.0-rc` 适合在受控本地或小范围试点环境中验证 SentinelFlow 的工具管理框架能力。

在进入更大范围试点前，仍应继续关注：

- 生产身份提供者替换
- API/Core 边界进一步收敛
- SSE token 传递方式加固
- 报告/导出敏感信息治理
- Store migration 版本化与恢复策略
- 更完整的浏览器自动化测试

这些事项已在 P5.5 审计和行动项中记录：

- [P5.5 Productization Audit](docs/release/p5_5_productization_audit.md)
- [P5.5 Action Items](docs/release/p5_5_action_items.md)
