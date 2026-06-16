# SentinelFlow 实现任务拆解路径

> 依据：《SentinelFlow 网络安全验证工具管理框架开发任务书 V2.0》  
> 产品英文名称：SentinelFlow  
> 文档用途：研发立项、任务排期、迭代跟踪、阶段验收  
> 规划基线：Rust Core + CLI First + 多语言 Adapter + API/Web Later  
> 安全边界：仅用于已授权资产、任务、人员和时间窗口内的安全验证

---

## 1. 规划结论

SentinelFlow 的首要目标不是实现扫描器，而是建立一套稳定、可验证、可扩展的工具管理框架。实现顺序必须遵循：

```text
标准协议冻结
  → Core 领域模型
  → CLI 与本地工作区
  → Command Adapter 单工具闭环
  → 结果、审计、报告闭环
  → 多适配器与 SDK
  → DAG 编排与 Policy
  → API Service
  → Web Console
  → 分布式与插件生态
```

项目的第一条关键路径是：

```text
Tool Manifest
  → Tool Registry
  → Command Adapter
  → Tool Run
  → Finding
  → Audit Event
  → Markdown Report
```

第二条关键路径是：

```text
Task Spec
  → Task Plan
  → Policy Check
  → DAG Execution
  → Step Data Mapping
  → Task Result
```

在两条关键路径跑通之前，不启动完整 Web Console、分布式 Worker、插件市场和 AI 分析。

---

## 2. 范围与边界

### 2.1 首版必须解决

1. 工具通过统一 Manifest 注册，而非写死在 Core 中。
2. 任务通过统一 Task Spec 描述。
3. 输入、输出、错误、证据和审计事件均可机器校验。
4. CLI 能完成工具校验、发现、执行、结果保存和报告导出。
5. 所有执行在授权和策略检查后进行。
6. 新增命令行工具时不修改 Core 代码。
7. 插件异常、超时或输出过量不能拖垮主进程。
8. CLI、未来 API 和 Web 复用同一套 Core。

### 2.2 首版明确不做

1. 自研扫描、漏洞利用、弱口令爆破或攻击链能力。
2. 未经审批的高风险能力自动执行。
3. 完整 Web UI 和复杂多租户权限系统。
4. 分布式调度、Kubernetes Worker 和插件市场。
5. 进程内加载不受信任动态库。
6. AI 自动决策或自动执行安全验证。

---

## 3. 名称与标识约定

产品英文名称正式统一为 `SentinelFlow`。技术标识采用同源命名，并遵循对应生态的大小写规则：

| 项目 | 规范值 |
|---|---|
| 产品英文名称 | `SentinelFlow` |
| CLI 二进制 | `sentinelflow` |
| 本地目录 | `.sentinelflow/` |
| Rust crate 前缀 | `sentinelflow-*` |
| 协议 API Group | `sentinelflow.io` |
| 环境变量前缀 | `SENTINELFLOW_` |

以上标识必须集中定义，禁止散落硬编码：

1. CLI 展示名称、目录名和环境变量前缀放入统一常量模块。
2. 协议对象统一使用 `apiVersion` 解析器，不在业务逻辑中比较裸字符串。
3. 文档、界面和发布物中的产品名称必须保持 `SentinelFlow` 的大小写形式。
4. CLI、crate、Python 包、工作目录和协议域使用表中规定的小写派生形式。
5. 不再提供或引入其他英文别名；历史标识迁移必须通过显式迁移逻辑完成。

---

## 4. 总体技术基线

### 4.1 推荐代码结构

```text
SentinelFlow/
  crates/
    sentinelflow-cli/              # CLI 参数、输出和交互
    sentinelflow-core/             # 用例编排与核心服务
    sentinelflow-schema/           # 协议对象、校验和版本迁移
    sentinelflow-runtime/          # 执行上下文、生命周期、进程控制
    sentinelflow-registry/         # 工具发现与注册中心
    sentinelflow-adapter-command/  # 本地命令/脚本适配
    sentinelflow-store/            # SQLite 和文件存储
    sentinelflow-policy/           # 授权与策略判断
    sentinelflow-orchestrator/     # DAG 编排，第二阶段启用
    sentinelflow-report/           # Markdown/JSON 导出
    sentinelflow-api/              # 后续 API Service
  sdk/
    python/
  schemas/
    v1alpha1/
  plugins/
    examples/
  docs/
  tests/
    fixtures/
    integration/
    e2e/
  Cargo.toml
```

### 4.2 核心模块边界

| 模块 | 职责 | 禁止承担 |
|---|---|---|
| Schema | 协议类型、结构校验、语义校验、版本迁移 | 工具执行 |
| Core | 组织用例和领域服务 | CLI 展示、具体工具逻辑 |
| Registry | 插件发现、Manifest 索引、启停和版本选择 | 直接运行工具 |
| Runtime | 生命周期、超时、取消、日志流、资源约束 | 解析具体业务结果 |
| Adapter | 将一种执行方式转换为统一运行协议 | 绕过 Policy 和 Audit |
| Normalizer | 原始结果转 Finding/Evidence/Error | 启动外部工具 |
| Policy | 授权范围、风险、时间窗、限速和审批判断 | 保存任务结果 |
| Store | 任务、运行、结果、审计的持久化 | 业务规则判断 |
| CLI/API | 输入输出适配和用户交互 | 重复实现 Core 逻辑 |

### 4.3 首版关键技术决策

1. 使用 Rust workspace 管理核心 crates。
2. 使用 `clap`、`serde`、`tokio`、`tracing`、`thiserror`、`sqlx` 和 SQLite。
3. 协议首版标记为 `sentinelflow.io/v1alpha1`。
4. JSON Schema 作为对外机器契约，Rust 类型与 Schema 在 CI 中执行一致性检查。
5. 结构校验之外增加语义校验，例如风险等级与审批要求的关联校验。
6. 插件首版全部运行在独立进程或容器中，不使用进程内动态库。
7. Core 通过 trait/port 依赖 Registry、Store、Adapter、Policy 和 Audit，便于 CLI/API 复用。
8. 默认拒绝未声明授权范围、高风险、超出时间窗和超出资源限制的执行。
9. 原始输出默认不保留；证据、敏感字段和保留周期由 Policy 控制。
10. 每次任务、运行、步骤和审计事件使用稳定 ID 与关联 ID。

---

## 5. 阶段与里程碑

以下工期按 3～4 名研发、1 名测试/安全评审兼职、双周迭代估算。团队规模变化时优先保持依赖顺序，不机械保持日期。

| 阶段 | 建议迭代 | 目标 | 退出里程碑 |
|---|---:|---|---|
| P0 工程与架构基线 | 1 个 Sprint | 建立可持续开发底座 | M0：工程可构建、测试、发布 |
| P1 协议与 CLI 骨架 | 1～2 个 Sprint | 冻结 `v1alpha1` 最小协议 | M1：可初始化、发现并校验工具 |
| P2 MVP 最小闭环 | 2～3 个 Sprint | 跑通单工具执行闭环 | M2：CLI MVP 可验收 |
| P3 多适配器与 SDK | 2 个 Sprint | 降低工具接入成本 | M3：至少三类接入方式可用 |
| P4 编排与策略控制 | 2～3 个 Sprint | 跑通多工具任务闭环 | M4：DAG 与安全策略可验收 |
| P5 API 与 Web Console | 3～4 个 Sprint | 提供团队化使用界面 | M5：Web Beta 可部署 |
| P6 生态与分布式 | 持续建设 | 插件可信、协同与规模化 | M6：生产生态版 |

建议先以 M2 为项目第一正式发布点，以 M4 为 `v1.0` 候选点。

---

## 6. P0：工程与架构基线

### 6.1 工作包

| ID | 任务 | 产出 | 依赖 |
|---|---|---|---|
| P0-01 | 初始化 Rust workspace 和 crate 空壳 | 可编译的仓库结构 | 无 |
| P0-02 | 统一格式、Lint、提交和版本规范 | `rustfmt`、`clippy`、约定文档 | P0-01 |
| P0-03 | 建立 CI | 构建、单测、Lint、Schema 检查 | P0-01 |
| P0-04 | 建立跨平台构建 | macOS/Linux 构建产物 | P0-03 |
| P0-05 | 编写架构决策记录 | ADR：插件隔离、Schema、存储、错误模型 | P0-01 |
| P0-06 | 建立威胁模型 | 信任边界、攻击面、默认拒绝规则 | P0-05 |
| P0-07 | 定义版本与发布策略 | crate、CLI、协议、插件版本规则 | P0-05 |
| P0-08 | 建立测试目录和 Fixture 规范 | 单测、集成、E2E 基线 | P0-03 |

### 6.2 完成标准

1. `cargo build --workspace`、`cargo test --workspace` 和 `cargo clippy` 全部通过。
2. CI 可在 macOS/Linux 或等价交叉构建环境生成二进制。
3. ADR 明确 Core 与 Adapter 的边界。
4. 威胁模型覆盖恶意参数、命令注入、路径穿越、敏感日志、资源耗尽和插件逃逸。
5. 仓库不得包含真实目标、真实凭据或高风险验证代码。

---

## 7. P1：协议体系与 CLI 骨架

### 7.1 协议工作包

| ID | 任务 | 关键内容 | 验收要点 |
|---|---|---|---|
| P1-01 | 定义公共元数据 | `apiVersion`、`kind`、metadata、extensions | 所有对象结构一致 |
| P1-02 | Tool Manifest | 身份、能力、运行时、输入输出、控制、审计、兼容性 | 可结构与语义校验 |
| P1-03 | Capability | 能力 ID、风险等级、影响类型、审批要求 | 枚举可扩展 |
| P1-04 | Tool Input | context、target、options、policy | 强制授权范围和目标类型 |
| P1-05 | Finding/Evidence | 目标、发现、严重性、置信度、证据 | 可表达示例工具结果 |
| P1-06 | Tool Output | 运行元数据、Findings、Errors、统计和原始输出引用 | JSON/JSONL 可统一解析 |
| P1-07 | Standard Error | 错误码、详情、可重试性、错误链 | CLI 可稳定映射退出码 |
| P1-08 | Audit Event | actor、resource、context、result、时间 | 覆盖关键动作 |
| P1-09 | Task Spec 最小版 | 单工具 steps、目标、授权和策略 | 可执行单步骤任务 |
| P1-10 | Policy 草案 | 授权、风险、时间窗、并发、保留策略 | 默认拒绝规则明确 |
| P1-11 | Schema 版本机制 | alpha/beta/v1、扩展字段、迁移入口 | 未知兼容字段可处理 |

### 7.2 CLI 与配置工作包

| ID | 任务 | 产出 |
|---|---|---|
| P1-12 | CLI 命令树 | `init/config/tool/plugin/task/result/report/audit` |
| P1-13 | 工作区初始化 | `.sentinelflow/` 标准目录和默认配置 |
| P1-14 | 分层配置加载 | 默认值 → 全局配置 → 项目配置 → 环境变量 → CLI 参数 |
| P1-15 | 配置诊断 | `config show`、配置来源、最终值、敏感字段遮蔽 |
| P1-16 | Schema 校验命令 | `tool validate`、`task validate` |
| P1-17 | 稳定退出码 | 成功、参数、Schema、授权、运行时、系统错误 |

### 7.3 设计门禁

P1 结束前必须组织一次协议评审，至少回答：

1. 新增工具是否无需修改 Core。
2. Command、Docker 和 HTTP 是否能共享同一 Manifest 主体。
3. 输入是否能表达授权范围、目标、限速和时间窗。
4. Finding 是否能表达资产发现、配置问题和风险验证结果。
5. Audit Event 是否能串联 task/run/step/tool。
6. 扩展字段是否不会破坏基础解析。
7. 协议中是否混入某个具体工具的私有字段。

P1 退出条件为 `v1alpha1` 最小协议冻结。冻结后新增字段优先采用可选字段，破坏性修改必须附迁移说明。

---

## 8. P2：CLI MVP 最小可运行闭环

### 8.1 工具注册与发现

| ID | 任务 | 关键实现 | 完成定义 |
|---|---|---|---|
| P2-01 | 插件目录扫描 | 本地目录发现、忽略规则、符号链接策略 | 可稳定发现示例插件 |
| P2-02 | Manifest 加载 | 解析、Schema 校验、语义校验 | 错误定位到字段 |
| P2-03 | 依赖检查 | 可执行文件、运行时、Schema、Parser | 缺失依赖时禁止启用 |
| P2-04 | Tool Registry | 注册、查询、启停、版本冲突处理 | `tool list/info` 可用 |
| P2-05 | 插件安装与校验 | 本地路径安装、幂等处理、完整性、安全项、兼容版本检查 | `plugin install/validate` 可用 |

### 8.2 Command Adapter 与 Runtime

| ID | 任务 | 关键实现 | 安全要求 |
|---|---|---|---|
| P2-06 | 统一 Adapter 接口 | prepare、execute、collect、cancel | 不暴露 Core 内部对象 |
| P2-07 | Command Adapter | 参数数组、工作目录、环境变量白名单 | 禁止拼接 shell 字符串 |
| P2-08 | 进程生命周期 | 启动、超时、取消、进程组终止 | 子进程必须可回收 |
| P2-09 | stdout/stderr 流 | 异步读取、大小限制、日志分级 | 防止内存耗尽 |
| P2-10 | 运行上下文 | task/run/operator/scope/correlation ID | 全链路可追踪 |
| P2-11 | 临时目录与文件 | 每次运行隔离、路径规范化、清理 | 防路径穿越 |
| P2-12 | 资源限制 | 超时、并发、输出上限 | 超限产生标准错误 |

脚本型工具在 MVP 中复用 Command Adapter，通过明确的解释器和参数数组执行，不单独建立重复运行时。

### 8.3 结果、存储、审计与报告

| ID | 任务 | 产出 | 验收要点 |
|---|---|---|---|
| P2-13 | Parser 调用约定 | JSON/JSONL 输入输出协议 | Parser 失败可定位 |
| P2-14 | 结果归一化 | Raw → Finding/Evidence/Error | 输出必须再次校验 |
| P2-15 | 本地文件存储 | runs/results/reports/audit 目录 | 原子写入、避免半文件 |
| P2-16 | SQLite 最小模型 | tools、tasks、runs、findings、audit_events | 支持状态查询 |
| P2-17 | Audit Sink | 关键动作统一写入 | 执行失败也有事件 |
| P2-18 | 日志落盘 | 结构化日志、运行日志、敏感字段遮蔽 | 可按 run_id 查询 |
| P2-19 | Markdown 报告 | 摘要、目标、发现、证据、错误、审计信息 | 空结果也能生成 |
| P2-20 | JSON/JSONL 导出 | 标准结果导出 | 导出结构通过 Schema |

### 8.4 CLI 用例

| ID | 命令 | 验收场景 |
|---|---|---|
| P2-21 | `sentinelflow init` | 初始化且重复执行不破坏已有配置 |
| P2-22 | `sentinelflow tool list/info` | 展示状态、版本、能力和风险 |
| P2-23 | `sentinelflow plugin install/validate` | 安装本地插件并输出结构、语义和安全校验结果 |
| P2-24 | `sentinelflow tool run` | 校验 → Policy → 执行 → 归一 → 保存 → 审计 |
| P2-25 | `sentinelflow task run` | 支持单步骤 Task Spec |
| P2-26 | `sentinelflow task status/logs` | 查询运行状态和日志 |
| P2-27 | `sentinelflow report generate` | 按 task/run 生成 Markdown 报告 |
| P2-28 | `sentinelflow audit list` | 按事件、时间、资源过滤 |
| P2-29 | `sentinelflow result normalize` | 对受支持的原始结果执行独立归一化 |
| P2-30 | `sentinelflow result export` | 导出标准 JSON/JSONL/Markdown |

### 8.5 示例插件

首版提供 3 个无攻击性的 Fixture/示例插件：

1. `example-echo`：验证输入、输出、错误和日志协议。
2. `example-dns-resolve`：演示命令/脚本适配和多条 Finding。
3. `example-file-import`：演示导入固定 Fixture 并归一化。

示例中不得包含真实凭据、生产目标或主动漏洞利用逻辑。

### 8.6 M2 验收闭环

```text
sentinelflow init
  → 放置示例插件
  → plugin validate
  → tool list
  → tool run
  → 生成标准 Finding
  → 保存 Run/Result
  → 写入 Audit Event
  → report generate
```

M2 必须同时通过以下异常路径：

1. Manifest 非法。
2. 目标不在授权范围。
3. 高风险工具未审批。
4. 工具不存在或依赖缺失。
5. 子进程超时。
6. 子进程异常退出。
7. 输出超过限制。
8. Parser 输出不符合 Schema。
9. 用户取消运行。
10. 报告面对空结果或部分失败任务。

---

## 9. P3：多适配器、归一化与 SDK

### 9.1 工作包

| ID | 任务 | 核心内容 | 优先级 |
|---|---|---|---|
| P3-01 | Adapter 能力协商 | 支持的输入、取消、流日志和资源控制能力 | P0 |
| P3-02 | Docker Adapter | 镜像、挂载、网络策略、资源限制、退出清理 | P0 |
| P3-03 | HTTP Adapter | 认证引用、重试、超时、分页、异步任务轮询 | P0 |
| P3-04 | File Import Adapter | JSON/JSONL/CSV 等受控导入 | P0 |
| P3-05 | 归一化管道 | validate、transform、enrich、deduplicate、persist | P0 |
| P3-06 | 去重策略 | 稳定 fingerprint、同源/跨工具去重规则 | P1 |
| P3-07 | 插件脚手架 | `plugin scaffold` | P0 |
| P3-08 | 插件测试工具 | Fixture、契约测试、快照测试 | P0 |
| P3-09 | Python SDK | 输入读取、输出写入、标准错误、测试辅助 | P0 |
| P3-10 | 插件版本管理 | 兼容范围、升级、回滚、并存规则 | P1 |
| P3-11 | 插件质量元数据 | experimental/community/verified/trusted/restricted | P1 |

### 9.2 适配器统一验收契约

每类 Adapter 必须通过相同的契约测试：

1. 接收统一 `ExecutionRequest`。
2. 返回统一状态、日志、原始输出引用和错误。
3. 支持超时和取消；不支持时必须显式声明。
4. 不得绕过 Policy、Audit 和 Result Normalizer。
5. 认证信息使用 Secret 引用，不写入 Manifest 或日志。
6. 失败不会破坏 Registry、Store 或其他任务。

### 9.3 M3 退出条件

1. Command、Docker、HTTP 三类 Adapter 至少各有一个可重复测试的示例。
2. Python SDK 可在不修改 Core 的情况下创建新插件。
3. `plugin scaffold → plugin test → plugin validate → tool run` 全链路通过。
4. Finding 去重规则具备稳定测试样例。

---

## 10. P4：DAG 编排与 Policy 控制

### 10.1 Task Planner

| ID | 任务 | 关键内容 |
|---|---|---|
| P4-01 | Task Spec 完整版 | 多步骤、dependsOn、inputFrom、outputAs、失败策略 |
| P4-02 | DAG 构建与校验 | 节点唯一、依赖存在、循环检测、不可达步骤 |
| P4-03 | 数据映射 | 上游标准结果到下游标准输入 |
| P4-04 | Dry Run | 工具、依赖、授权、策略、预计执行顺序 |
| P4-05 | 计划快照 | 实际运行绑定不可变计划，避免中途配置漂移 |

### 10.2 Scheduler

| ID | 任务 | 关键内容 |
|---|---|---|
| P4-06 | DAG 调度 | 就绪队列、并发节点、依赖状态传播 |
| P4-07 | 并发控制 | 全局、任务、工具三级并发限制 |
| P4-08 | 速率限制 | 按工具、目标或策略分组 |
| P4-09 | 重试策略 | 可重试错误、退避、最大次数、幂等性提示 |
| P4-10 | 失败策略 | stop/continue/skip-dependent |
| P4-11 | 暂停、终止、恢复 | 状态机、检查点、重复恢复保护 |

### 10.3 Policy 与授权

| ID | 任务 | 关键内容 |
|---|---|---|
| P4-12 | 授权范围模型 | 目标类型、范围、有效期、授权主体 |
| P4-13 | 目标匹配器 | 域名、URL、IP/CIDR 的规范化和边界判断 |
| P4-14 | 风险决策 | riskLevel、impact、环境与审批组合判断 |
| P4-15 | 时间窗口 | 时区、跨午夜、计划与实际执行时间 |
| P4-16 | 审批接口 | request/approve/reject/expire，暂以 Core/API 接口实现 |
| P4-17 | 输出策略 | 原始输出、脱敏、证据保留周期 |
| P4-18 | Policy Explain | 返回允许/拒绝的规则和原因 |

Policy 执行点至少包括：

```text
任务创建
  → 计划生成
  → 运行开始
  → 每个步骤开始
  → 输出保存
  → 报告导出
```

不能只在任务开始时检查一次，因为授权、时间窗和审批状态可能在排队期间变化。

### 10.4 M4 验收闭环

```text
task validate
  → task plan
  → 授权与 Policy Explain
  → DAG 调度
  → 步骤间传递标准结果
  → 局部失败处理
  → Finding 汇总
  → 审计与报告
```

M4 是 `v1.0` 候选门槛。必须通过循环依赖、越权目标、高风险未审批、跨午夜时间窗、部分失败、取消恢复和配置漂移测试。

---

## 11. P5：API Service 与 Web Console

### 11.1 API Service

| ID | 任务 | 产出 |
|---|---|---|
| P5-01 | Core Application Service | CLI/API 共用用例层 |
| P5-02 | REST API | tools、plugins、tasks、runs、findings、reports、audit、approvals |
| P5-03 | OpenAPI | 版本化接口文档与客户端生成基础 |
| P5-04 | 实时日志 | WebSocket 或 SSE |
| P5-05 | 认证与会话 | 接入可替换身份提供方 |
| P5-06 | RBAC | viewer/operator/approver/admin 最小角色 |
| P5-07 | API 审计 | actor、client、request correlation |
| P5-08 | 服务部署 | 单机模式、数据库迁移、健康检查 |

### 11.2 Web Console

按以下顺序实现页面，避免先做展示性大屏：

1. 登录与工作区。
2. 工具列表、详情、Manifest、启停。
3. 插件安装、校验、测试和依赖状态。
4. Task Spec 编辑、校验和计划预览。
5. 任务运行、日志、步骤状态和终止。
6. Finding、Evidence 和报告。
7. 审批处理。
8. Audit 和 Policy Explain。
9. 系统配置与标准协议中心。

### 11.3 M5 退出条件

1. Web 不直接启动工具，只调用 API/Core。
2. CLI 与 Web 对同一任务得到一致的计划和 Policy 结果。
3. API 关键操作均有认证、授权和审计。
4. 任务日志断线重连后可继续查看。
5. Web 可完成从插件校验到报告查看的完整流程。

---

## 12. P6：生态、协同与分布式

P6 不应一次性展开，按真实使用需求逐项立项：

| 方向 | 前置条件 | 主要任务 |
|---|---|---|
| 插件可信体系 | 插件版本模型稳定 | 包格式、签名、校验和、来源证明、质量分级 |
| 插件仓库/市场 | 可信体系完成 | 索引、搜索、兼容性、下载、升级、撤回 |
| 分布式 Worker | 单机状态机稳定 | Worker 注册、心跳、能力标签、任务租约、结果回传 |
| 团队空间 | 身份与 RBAC 稳定 | Workspace、项目、成员、授权范围隔离 |
| 外部系统集成 | API 稳定 | CMDB、工单、SIEM/SOC、对象存储 |
| 知识库与规则库 | Finding 模型稳定 | 版本、来源、审核、兼容性 |
| AI 辅助分析 | 数据治理完成 | 结果摘要、报告草稿、证据引用、人工确认 |

AI 能力仅用于解释、归纳和辅助编写，不得绕过 Policy 自动扩大目标、提高风险等级或执行高风险工具。

---

## 13. 横向保障任务

以下工作不是独立末期阶段，应从 P0 开始贯穿每个里程碑。

### 13.1 测试体系

| 测试层 | 覆盖内容 |
|---|---|
| 单元测试 | Schema、状态机、Policy 规则、目标匹配、去重 |
| 契约测试 | Adapter、Parser、Store、Audit Sink |
| 集成测试 | Registry + Runtime + Store + Normalizer |
| E2E | CLI 两个最小闭环及异常路径 |
| 快照测试 | CLI 输出、Markdown 报告、示例 Schema |
| 安全测试 | 注入、路径穿越、敏感信息、资源耗尽、越权 |
| 兼容测试 | macOS/Linux、协议版本、插件版本 |
| 迁移测试 | SQLite Schema、协议对象和配置升级 |

每修复一个执行、解析、策略或状态机缺陷，必须增加回归测试。

### 13.2 可观测性

1. 统一结构化日志字段：`task_id`、`run_id`、`step_id`、`tool_id`、`actor_id`。
2. 明确用户日志、运行日志、审计日志的边界。
3. 敏感字段在进入日志系统前完成遮蔽。
4. 记录执行耗时、等待耗时、解析耗时、结果数量和错误分类。
5. API 阶段增加指标接口和健康检查。

### 13.3 文档

每个阶段同步维护：

1. 快速开始。
2. CLI 参考。
3. 协议规范和 Schema 示例。
4. 插件开发与测试指南。
5. Adapter 开发指南。
6. 安全边界和授权操作说明。
7. 架构决策记录。
8. 版本升级与迁移指南。

### 13.4 发布

1. 使用语义化版本管理 CLI/Core。
2. 协议版本和程序版本分开管理。
3. 生成 macOS/Linux 校验和与发布说明。
4. 发布前执行 E2E、Schema 兼容、数据库迁移和安全检查。
5. `v1.0` 前不承诺 alpha 协议完全稳定，但每次破坏性变更必须提供迁移工具或明确说明。

---

## 14. MVP 优先级清单

### P0：M2 发布阻塞项

1. `v1alpha1` Tool Manifest、Capability、Input、Output、Finding、Evidence、Error、Audit Event、Task Spec 和 Policy。
2. CLI 初始化、校验、工具查询、工具执行、任务执行、报告和审计命令。
3. Tool Registry。
4. Command Adapter。
5. Runtime 超时、取消、日志和输出限制。
6. 默认拒绝的最小 Policy。
7. 标准结果归一化。
8. SQLite 与文件存储。
9. Markdown 报告。
10. 3 个安全示例插件。
11. macOS/Linux 构建。
12. E2E 正常及异常路径。

### P1：M2 后尽快完成

1. Docker Adapter。
2. HTTP Adapter。
3. File Import Adapter。
4. Python SDK 与脚手架。
5. 结果去重。
6. 任务日志查询增强。
7. 插件版本管理。

### P2：延后到需求验证后

1. 完整 Web Console。
2. 插件市场。
3. 分布式 Worker。
4. 多租户。
5. OpenSearch、Redis、MinIO。
6. AI 辅助分析。

---

## 15. 推荐迭代拆分

### Sprint 0：工程启动

1. 建立 workspace、CI、Lint、测试和发布骨架。
2. 完成 ADR 和初版威胁模型。
3. 确定名称隔离策略和协议版本策略。

### Sprint 1：协议与初始化

1. 完成公共元数据、Manifest、Input、Finding、Error 和 Audit Event。
2. 完成 `.sentinelflow/` 初始化和配置加载。
3. 完成 `tool validate`、`task validate`。

### Sprint 2：发现与执行

1. 完成插件扫描、Registry 和依赖检查。
2. 完成 Command Adapter、运行上下文和进程控制。
3. 完成 `tool list/info/run`。

### Sprint 3：结果闭环

1. 完成 Parser、Normalizer、SQLite、文件存储和 Audit Sink。
2. 完成 Markdown 报告。
3. 完成示例插件和单工具 E2E。

### Sprint 4：MVP 稳定

1. 完成单步骤 Task Spec 与 `task run/status/logs`。
2. 补齐异常路径、安全测试和跨平台发布。
3. 完成 CLI、协议和插件开发文档。
4. 发布 M2。

### Sprint 5～6：接入扩展

1. Docker、HTTP、File Import Adapter。
2. Python SDK、脚手架、插件测试和版本管理。
3. 发布 M3。

### Sprint 7～9：编排与策略

1. DAG、数据映射、Dry Run。
2. 并发、限速、重试、暂停和恢复。
3. 授权范围、高风险审批和 Policy Explain。
4. 发布 M4 / `v1.0-rc`。

API 和 Web 在 M4 后单独排期，避免界面开发反向固化尚未稳定的 Core 接口。

---

## 16. 团队任务分工建议

| 角色 | 主要职责 |
|---|---|
| Core/架构 | Schema、Core、Runtime、状态机、代码评审 |
| CLI/Adapter | CLI、Registry、Command/Docker/HTTP Adapter、SDK |
| 数据/平台 | SQLite、文件存储、迁移、报告、后续 API |
| 测试/安全 | 契约测试、E2E、威胁模型、越权与资源限制验证 |
| 产品/技术写作 | 协议示例、插件指南、验收场景、版本说明 |

若只有 1～2 名研发，按 P0 → P1 → P2 串行推进，先缩减 Adapter 数量，不缩减 Schema、Policy、Audit 和异常测试。

---

## 17. Definition of Done

任何工作包只有同时满足以下条件才算完成：

1. 代码已合入正确模块，没有把具体工具逻辑写入 Core。
2. 正常路径和关键异常路径有自动化测试。
3. 对外协议、CLI 或数据库变化有文档和迁移说明。
4. 关键动作产生 Audit Event。
5. 日志不包含凭据、令牌或未脱敏敏感数据。
6. 新增执行路径经过 Policy。
7. 新增输出经过 Schema 校验和 Normalizer。
8. `cargo fmt`、`clippy`、单测和相关 E2E 通过。
9. macOS/Linux 兼容性得到验证。
10. 验收示例可在干净环境中重复运行。

---

## 18. 主要风险与应对

| 风险 | 表现 | 应对 |
|---|---|---|
| 协议过早复杂化 | 首版难以落地，字段大量闲置 | 先冻结最小 `v1alpha1`，用真实示例验证 |
| Schema 与 Rust 类型漂移 | 校验和运行行为不一致 | CI 自动生成/对比并执行双向 Fixture 测试 |
| Core 与工具耦合 | 每接一个工具都修改核心 | 只通过 Adapter、Parser 和 Manifest 扩展 |
| 插件影响主进程 | 崩溃、阻塞、内存耗尽 | 外部进程隔离、超时、输出和资源限制 |
| 授权判断不严谨 | 域名/IP 边界匹配错误 | 规范化目标，使用结构化解析器和边界测试 |
| 审计只记成功路径 | 失败和拒绝无法追溯 | 在用例入口、Policy、Runtime 和 Store 分层记录 |
| DAG 状态失控 | 重试、取消、恢复后状态不一致 | 明确状态机、幂等键和计划快照 |
| Web 过早开始 | Core 接口被页面需求绑死 | M4 前只做 Core/CLI，不建设完整 Web |
| 多语言维护成本 | SDK 行为不一致 | 契约测试作为所有 SDK/Adapter 的共同门禁 |
| 名称变更成本 | CLI、目录、协议域散落 | 集中常量，`v1` 前完成最终命名 |

---

## 19. 阶段验收总表

| 里程碑 | 必须可演示 | 必须可验证 |
|---|---|---|
| M0 | 构建、测试、生成二进制 | CI、跨平台、威胁模型 |
| M1 | 初始化、校验 Manifest/Task | Schema、语义校验、稳定错误 |
| M2 | 单工具到报告完整闭环 | 授权拒绝、超时、取消、解析失败、审计 |
| M3 | 多适配器和 SDK 接入 | 统一 Adapter 契约、插件不改 Core |
| M4 | 多步骤 DAG 和 Policy | 循环检测、数据传递、审批、恢复 |
| M5 | Web 完整操作闭环 | CLI/API 一致、认证授权、实时日志 |
| M6 | 可信插件和 Worker | 签名、租约、隔离、团队权限 |

---

## 20. 开工顺序

项目启动后，前十项任务应严格按以下顺序推进：

1. 固化 SentinelFlow 命名与集中常量策略。
2. 建立 Rust workspace、CI 和跨平台构建。
3. 完成核心 ADR 和威胁模型。
4. 定义公共协议元数据及错误模型。
5. 定义 Tool Manifest、Input、Finding、Evidence、Audit Event。
6. 建立 Schema Fixture 与兼容性测试。
7. 实现工作区初始化和分层配置。
8. 实现插件发现、Manifest 校验和 Tool Registry。
9. 实现 Command Adapter 与受控 Runtime。
10. 接通 Normalizer、Store、Audit 和 Markdown Report。

完成以上十项后，优先发布可使用的 CLI MVP，再继续扩展 Adapter 和 DAG。此路径能够最早验证任务书中的核心假设：

> 不修改核心代码，即可将一个外部安全验证工具以标准方式接入、受控执行、归一输出、审计留痕并生成报告。
