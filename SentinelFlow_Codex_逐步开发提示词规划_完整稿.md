# SentinelFlow Codex 逐步开发提示词规划

> 文档用途：将《SentinelFlow 网络安全验证工具管理框架开发任务书 V2.0》和《SentinelFlow 实现任务拆解路径》整理为可直接投喂 Codex 的分阶段开发提示词体系。  
> 核心原则：不要一次性让 Codex 开发完整产品，而是用“总控规则 + 阶段任务 + 验收闭环”的方式逐步实现一个可靠、强壮、可持续进化的产品。  
> 产品定位：SentinelFlow 是网络安全验证工具管理框架，不是扫描器、漏洞利用器或攻击平台。  

---

## 1. 使用方式

建议将本提示词体系拆成三类使用：

1. **总控规则**：放入项目根目录 `AGENTS.md` 或 `CODEX.md`，让 Codex 长期遵守。
2. **固定任务模板**：每次给 Codex 派发任务时套用，防止它越界实现。
3. **阶段提示词**：按 P0 → P1 → P1.5 → P2 → P3 → P4 → P5 逐步执行。

推荐开工顺序：

```text
AGENTS.md / CODEX.md 总控规则
→ P0 工程骨架
→ P1 协议对象与 Schema
→ P1.5 CLI 初始化与校验
→ P2-1 插件发现与 Tool Registry
→ P2-2 Command Adapter 与 Runtime
→ P2-3 Normalizer / Store / Audit / Report
→ P2-4 单步骤 Task MVP
→ P3 多 Adapter 与 SDK
→ P4 DAG 与 Policy
→ P5 API / Web Console
```

第一阶段真正要跑通的不是“大而全功能”，而是这个最小闭环：

```text
sentinelflow init
→ plugin validate
→ plugin install
→ tool list
→ tool run
→ Parser
→ Finding
→ Audit Event
→ Markdown Report
```

---
# 2. 总控提示词：建议保存为 AGENTS.md 或 CODEX.md

```md
你是 SentinelFlow 项目的核心开发工程师。

项目定位：
SentinelFlow 是一个网络安全验证工具管理框架，不是扫描器、漏洞利用器或攻击平台。它的核心目标是为外部安全验证工具提供统一接入、统一注册、统一执行、统一输出、统一审计、统一策略控制和持续扩展能力。

必须遵守：
1. 产品英文名称统一为 SentinelFlow。
2. CLI 二进制名称为 sentinelflow。
3. 本地工作目录为 .sentinelflow/。
4. 协议 API Group 使用 sentinelflow.io。
5. Rust crate 前缀使用 sentinelflow-*。
6. 第一阶段只做 Rust Core + CLI + 标准协议 + Command Adapter。
7. 不要开发真实扫描器、漏洞利用、弱口令爆破、持久化、隐蔽探测、认证绕过或攻击链自动化能力。
8. 所有工具能力必须通过 Manifest + Adapter + Parser 接入。
9. 新增工具不得修改 Core。
10. 所有执行必须经过 Policy 检查。
11. 所有关键动作必须写入 Audit Event。
12. 所有输出必须经过 Schema 校验和 Normalizer。
13. 插件不得进程内加载不受信任动态库，首版只能通过独立进程或后续容器执行。
14. Web/API 不能重复实现 Core 逻辑，只能复用 Core。
15. 每次实现必须包含测试、文档和可运行验收命令。

技术基线：
- Rust workspace
- crates:
  - sentinelflow-cli
  - sentinelflow-core
  - sentinelflow-schema
  - sentinelflow-runtime
  - sentinelflow-registry
  - sentinelflow-adapter-command
  - sentinelflow-store
  - sentinelflow-policy
  - sentinelflow-report
  - sentinelflow-orchestrator
  - sentinelflow-api
- SDK 后续放在 sdk/python/
- Schema 放在 schemas/v1alpha1/
- 示例插件放在 plugins/examples/
- 测试放在 tests/fixtures、tests/integration、tests/e2e

开发原则：
1. 每次只完成当前任务，不提前做后续阶段。
2. 先读现有代码，再修改。
3. 修改前先给出实现计划。
4. 修改后必须说明改了哪些文件、为什么这样设计、如何测试。
5. 必须运行或说明以下命令：
   - cargo fmt --all
   - cargo clippy --workspace --all-targets
   - cargo test --workspace
6. 所有新增协议、CLI 命令、数据库结构变化必须同步更新文档。
7. 所有安全边界必须默认拒绝。
8. 所有错误必须使用标准错误模型，不允许随意 panic。
```

---
# 3. 每次发给 Codex 的固定任务模板

```md
你现在只完成 SentinelFlow 的【阶段/任务编号：XXX】。

背景：
- SentinelFlow 是网络安全验证工具管理框架，不是具体扫描器。
- 当前只允许实现本任务，不要实现后续阶段。
- 必须遵守 AGENTS.md / CODEX.md 中的项目规则。

本次目标：
【写清楚本次只做什么】

必须交付：
1. 代码实现。
2. 单元测试/集成测试/E2E 测试。
3. 文档更新。
4. 示例文件或 Fixture。
5. 验收命令。

禁止事项：
1. 不要实现真实漏洞扫描、利用、爆破、持久化、隐蔽探测。
2. 不要把具体工具逻辑写进 Core。
3. 不要绕过 Policy、Audit、Normalizer。
4. 不要提前做 Web、分布式、插件市场、AI 分析。
5. 不要使用 shell 字符串拼接执行外部命令，必须使用参数数组。

请按以下格式输出：
1. 当前仓库理解。
2. 实现计划。
3. 修改文件列表。
4. 关键实现说明。
5. 测试说明。
6. 验收命令。
7. 遗留风险和下一步建议。
```

---
# 4. P0：工程与架构基线

```md
你现在执行 SentinelFlow 的 P0 工程与架构基线任务。

目标：
建立一个可持续开发的 Rust workspace，不实现具体业务能力。

请完成：
1. 初始化 Rust workspace。
2. 创建以下 crate 空壳：
   - sentinelflow-cli
   - sentinelflow-core
   - sentinelflow-schema
   - sentinelflow-runtime
   - sentinelflow-registry
   - sentinelflow-adapter-command
   - sentinelflow-store
   - sentinelflow-policy
   - sentinelflow-report
   - sentinelflow-orchestrator
   - sentinelflow-api
3. 创建目录：
   - schemas/v1alpha1/
   - plugins/examples/
   - docs/
   - tests/fixtures/
   - tests/integration/
   - tests/e2e/
4. 建立统一常量模块，集中定义：
   - Product Name: SentinelFlow
   - CLI Binary: sentinelflow
   - Workspace Dir: .sentinelflow
   - API Group: sentinelflow.io
   - Env Prefix: SENTINELFLOW_
5. 配置 rustfmt、clippy、基础 CI。
6. 编写 docs/adr/0001-architecture-baseline.md。
7. 编写 docs/security-boundary.md，说明默认拒绝、授权边界、插件隔离、禁止真实攻击能力。
8. 添加最小测试，保证 workspace 可构建。

验收：
- cargo build --workspace 通过
- cargo test --workspace 通过
- cargo clippy --workspace --all-targets 通过
- 仓库中不得出现真实目标、真实凭据或攻击代码
```

---
# 5. P1：协议体系与 Schema

```md
你现在执行 SentinelFlow 的 P1 协议体系任务。

目标：
实现 sentinelflow.io/v1alpha1 最小协议，不实现工具执行。

请完成：
1. 在 sentinelflow-schema 中定义协议对象：
   - Common Metadata
   - Tool Manifest
   - Capability
   - Tool Input
   - Tool Output
   - Finding
   - Evidence
   - Standard Error
   - Audit Event
   - Task Spec 最小版
   - Policy 草案
2. 所有对象必须支持：
   - apiVersion
   - kind
   - metadata
   - extensions
3. 在 schemas/v1alpha1/ 下生成或维护 JSON Schema。
4. 增加结构校验和语义校验：
   - apiVersion 必须合法
   - kind 必须匹配
   - 高风险能力必须 requiresApproval=true
   - tool runtime 必须声明 mode
   - input/output schema 路径必须可解析
   - Task Spec 必须声明 authorizationScope
5. 增加 Fixture：
   - 合法 Tool Manifest
   - 非法 Tool Manifest
   - 合法 Task Spec
   - 非法 Task Spec
   - 合法 Finding
   - 非法 Finding
6. 增加测试，验证 Rust 类型和 JSON Schema 行为一致。

禁止：
- 不要实现 CLI 执行工具
- 不要实现 Runtime
- 不要实现 Web/API
- 不要写任何真实安全扫描逻辑

验收：
- cargo test --workspace 通过
- 能通过测试证明合法 Fixture 通过、非法 Fixture 拒绝
- 错误信息必须能定位到字段
```

---
# 6. P1.5：CLI 骨架与工作区初始化

```md
你现在执行 SentinelFlow 的 P1.5 CLI 骨架任务。

目标：
实现 CLI 命令树和 .sentinelflow 工作区初始化，不执行工具。

请完成：
1. 使用 clap 实现 sentinelflow CLI。
2. 命令树包括：
   - init
   - config show
   - tool validate
   - task validate
   - tool list
   - tool info
   - plugin validate
   - plugin install
   - tool run
   - task run
   - task plan
   - task status
   - task logs
   - result normalize
   - result export
   - report generate
   - audit list
3. 当前阶段只需要真正实现：
   - sentinelflow init
   - sentinelflow config show
   - sentinelflow tool validate
   - sentinelflow task validate
4. 其他命令可以返回明确的 NotImplemented 标准错误。
5. init 创建：
   - .sentinelflow/config.yaml
   - .sentinelflow/plugins/
   - .sentinelflow/tools/
   - .sentinelflow/tasks/
   - .sentinelflow/runs/
   - .sentinelflow/results/
   - .sentinelflow/reports/
   - .sentinelflow/audit/
6. 实现分层配置加载：
   - 默认值
   - 项目配置
   - 环境变量
   - CLI 参数
7. config show 需要遮蔽敏感字段。
8. 定义稳定退出码：
   - 0 成功
   - 2 参数错误
   - 3 Schema 错误
   - 4 授权/策略错误
   - 5 运行时错误
   - 6 系统错误

验收：
- sentinelflow init 可重复执行且不破坏已有配置
- sentinelflow config show 可展示最终配置
- sentinelflow tool validate 可校验 Manifest Fixture
- sentinelflow task validate 可校验 Task Spec Fixture
```

---
# 7. P2-1：插件发现与 Tool Registry

```md
你现在执行 SentinelFlow 的 P2-1 插件发现与 Tool Registry 任务。

目标：
让框架能够发现、校验、注册工具，但暂不执行工具。

请完成：
1. 实现插件目录扫描：
   - 默认扫描 .sentinelflow/plugins/
   - 支持 plugins/examples/
   - 忽略隐藏目录、临时文件、非法符号链接
2. 插件目录结构：
   - sentinelflow.tool.yaml
   - runner/
   - parser/
   - schemas/
   - examples/
   - README.md
3. 实现 Manifest 加载：
   - YAML 解析
   - JSON Schema 校验
   - 语义校验
   - 兼容版本检查
4. 实现依赖检查：
   - runner 是否存在
   - parser 是否存在
   - input/output schema 是否存在
   - runtime mode 是否受支持
5. 实现 Tool Registry：
   - 注册
   - 查询
   - 启用/禁用状态
   - 版本冲突处理
6. 实现 CLI：
   - sentinelflow plugin validate <path>
   - sentinelflow plugin install <path>
   - sentinelflow tool list
   - sentinelflow tool info <tool>
7. 提供 example-echo 插件，但该插件只做安全的 echo，不做任何扫描。

验收：
- plugin validate 能输出结构校验、语义校验、安全校验结果
- plugin install 幂等
- tool list 能显示工具名称、版本、能力、风险等级、启用状态
- tool info 能显示 Manifest 关键信息
- 新增 example-echo 不需要修改 Core 代码
```

---
# 8. P2-2：Command Adapter 与受控 Runtime

```md
你现在执行 SentinelFlow 的 P2-2 Command Adapter 与 Runtime 任务。

目标：
实现受控执行本地命令/脚本插件的能力，但只允许执行示例插件，不实现真实扫描。

请完成：
1. 定义统一 Adapter trait：
   - prepare
   - execute
   - collect
   - cancel
2. 实现 Command Adapter：
   - 使用参数数组执行命令
   - 禁止 shell 字符串拼接
   - 控制 working directory
   - 环境变量白名单
   - stdout/stderr 异步读取
   - 输出大小限制
   - 超时控制
   - 进程组终止
   - 临时目录隔离
   - 路径规范化，防路径穿越
3. 定义 ExecutionRequest / ExecutionResult。
4. 每次运行必须生成：
   - task_id
   - run_id
   - step_id
   - tool_id
   - correlation_id
5. 实现最小 Policy 检查：
   - 未声明 authorizationScope 拒绝
   - high/critical 风险默认拒绝
   - 超过 timeout 拒绝或终止
6. 实现 CLI：
   - sentinelflow tool run <tool> --input input.json
7. example-echo 插件可以被执行，并输出受控 JSON。

禁止：
- 不要执行任意 shell
- 不要允许插件绕过 Policy
- 不要保留敏感原始输出
- 不要引入真实扫描工具

验收异常路径：
- 工具不存在
- Manifest 非法
- runner 不存在
- 输入不符合 Schema
- 未声明授权范围
- 高风险工具未审批
- 子进程超时
- 子进程异常退出
- 输出超过限制
- 用户取消运行
```

---
# 9. P2-3：结果、审计、报告闭环

```md
你现在执行 SentinelFlow 的 P2-3 结果、审计、报告闭环任务。

目标：
跑通从 tool run 到 Finding、Audit Event、Markdown Report 的完整闭环。

请完成：
1. 实现 Parser 调用约定：
   - 输入：原始输出引用 + 执行上下文
   - 输出：标准 Tool Output / Finding / Error
2. 实现 Normalizer：
   - Raw → Finding
   - Raw → Evidence
   - Raw → Standard Error
   - 输出后再次 Schema 校验
3. 实现文件存储：
   - .sentinelflow/runs/
   - .sentinelflow/results/
   - .sentinelflow/reports/
   - .sentinelflow/audit/
   - 原子写入，避免半文件
4. 实现 SQLite 最小模型：
   - tools
   - tasks
   - runs
   - findings
   - audit_events
5. 实现 Audit Sink：
   - tool.run.requested
   - policy.denied
   - tool.run.started
   - tool.run.finished
   - tool.run.failed
   - result.normalized
   - report.generated
6. 实现日志落盘：
   - task_id
   - run_id
   - step_id
   - tool_id
   - actor_id
   - correlation_id
7. 实现 Markdown 报告：
   - 摘要
   - 目标
   - 工具
   - Findings
   - Evidence
   - Errors
   - Audit 摘要
8. 实现 CLI：
   - sentinelflow report generate --run <run_id>
   - sentinelflow audit list
   - sentinelflow result export --format json|jsonl|md

验收：
- tool run example-echo 后能生成 Finding
- 能保存 Run、Result、Audit Event
- 能生成 Markdown 报告
- 空结果也能生成报告
- Parser 输出非法时能产生标准错误和审计事件
```

---
# 10. P2-4：单步骤 Task Spec MVP

```md
你现在执行 SentinelFlow 的 P2-4 单步骤 Task Spec MVP 任务。

目标：
实现单步骤 task run，发布第一个可验收 CLI MVP。

请完成：
1. 实现 Task Spec 最小执行：
   - metadata
   - authorizationScope
   - targets
   - steps
   - policy
2. 支持单步骤任务：
   - 一个 task
   - 一个 tool
   - 一个或多个 target
3. 实现：
   - sentinelflow task run task.yaml
   - sentinelflow task status <task_id>
   - sentinelflow task logs <task_id>
4. task run 流程：
   - 读取 Task Spec
   - Schema 校验
   - Policy 校验
   - Tool Registry 查询
   - 构造 Tool Input
   - Command Adapter 执行
   - Parser 解析
   - Normalizer 归一
   - Store 保存
   - Audit 写入
   - Report 可生成
5. 提供 3 个安全示例插件：
   - example-echo
   - example-dns-resolve，允许只解析本地 Fixture 或安全 mock，不做主动扫描
   - example-file-import
6. 补齐 E2E：
   - init
   - plugin validate
   - plugin install
   - tool list
   - tool run
   - task run
   - report generate
   - audit list

验收：
必须跑通：
sentinelflow init
sentinelflow plugin validate plugins/examples/example-echo
sentinelflow plugin install plugins/examples/example-echo
sentinelflow tool list
sentinelflow tool run example-echo --input tests/fixtures/input.example.json
sentinelflow task run tests/fixtures/task.single-step.yaml
sentinelflow report generate --task <task_id>
sentinelflow audit list

同时通过异常路径：
- Manifest 非法
- 目标不在授权范围
- 高风险工具未审批
- 工具不存在
- 依赖缺失
- 子进程超时
- 输出超过限制
- Parser 输出不符合 Schema
- 用户取消运行
- 空结果报告
```

---
# 11. P3：多适配器与 Python SDK

```md
你现在执行 SentinelFlow 的 P3 多适配器与 SDK 任务。

前提：
P2 CLI MVP 已完成并通过验收。

目标：
降低外部工具接入成本，但仍不实现具体扫描能力。

请完成：
1. 设计 Adapter 能力协商：
   - 是否支持取消
   - 是否支持流日志
   - 是否支持资源限制
   - 是否支持异步任务
2. 实现 Docker Adapter：
   - 镜像
   - 挂载目录
   - 网络策略
   - CPU/内存限制
   - 超时和清理
3. 实现 HTTP Adapter：
   - URL
   - method
   - headers
   - secret 引用
   - timeout
   - retry
   - pagination
   - async polling
4. 实现 File Import Adapter：
   - JSON
   - JSONL
   - CSV
   - 受控导入
5. 实现 Python SDK：
   - 读取标准输入
   - 写入标准输出
   - 生成标准错误
   - 生成 Finding/Evidence
   - 测试辅助工具
6. 实现：
   - sentinelflow plugin scaffold
   - sentinelflow plugin test
7. 增加契约测试：
   - Command Adapter
   - Docker Adapter
   - HTTP Adapter
   - File Import Adapter
8. 增加 Finding 去重：
   - 稳定 fingerprint
   - 同工具去重
   - 跨工具去重基础策略

禁止：
- 认证信息不得写入 Manifest 明文
- Adapter 不得绕过 Policy、Audit、Normalizer
- 不要接入真实攻击性工具

验收：
- plugin scaffold → plugin test → plugin validate → tool run 全链路通过
- Command/Docker/HTTP/File Import 至少各有一个安全示例
- 新增 Python SDK 插件不需要修改 Core
```

---
# 12. P4：DAG 编排与 Policy 强化

```md
你现在执行 SentinelFlow 的 P4 DAG 编排与 Policy 控制任务。

目标：
实现多步骤任务编排和更强策略控制，作为 v1.0-rc 候选基础。

请完成：
1. Task Spec 完整版：
   - 多 steps
   - dependsOn
   - inputFrom
   - outputAs
   - failurePolicy
2. DAG Planner：
   - 节点唯一校验
   - 依赖存在校验
   - 循环检测
   - 不可达步骤检测
   - 执行顺序预览
3. 实现：
   - sentinelflow task plan task.yaml
4. Scheduler：
   - 就绪队列
   - 并发节点
   - 依赖状态传播
   - stop/continue/skip-dependent
5. Policy 强化：
   - 授权范围模型
   - 域名/URL/IP/CIDR 目标匹配器
   - 风险等级决策
   - 时间窗口，支持跨午夜
   - 并发限制
   - 速率限制
   - 输出保留策略
   - Policy Explain
6. 审批接口：
   - request
   - approve
   - reject
   - expire
   当前可先做 Core/CLI 接口，不做 Web。
7. 状态机：
   - pending
   - planning
   - running
   - paused
   - cancelling
   - cancelled
   - failed
   - completed
8. 支持取消和恢复的基础能力。
9. 增加计划快照，避免运行中配置漂移。

验收：
- task validate
- task plan
- task run 多步骤任务
- 上一步 Finding 可映射为下一步输入
- 循环依赖会被拒绝
- 越权目标会被拒绝
- 高风险未审批会被拒绝
- 跨午夜时间窗正确判断
- 部分失败策略正确
- 取消和恢复不会造成状态错乱
```

---
# 13. P5：API Service 与 Web Console

```md
你现在执行 SentinelFlow 的 P5 API Service 与 Web Console 任务。

前提：
P4 DAG 与 Policy 已稳定。

目标：
提供团队化使用界面，但 Web 只能调用 API/Core，不能直接执行工具。

请完成：
1. API Service：
   - tools
   - plugins
   - tasks
   - runs
   - findings
   - reports
   - audit
   - approvals
2. OpenAPI 文档。
3. 实时日志：
   - WebSocket 或 SSE
4. 认证与会话：
   - 先实现可替换身份提供方接口
5. 最小 RBAC：
   - viewer
   - operator
   - approver
   - admin
6. Web 页面按顺序实现：
   - 登录与工作区
   - 工具列表/详情/Manifest
   - 插件安装/校验/测试
   - Task Spec 编辑/校验/计划预览
   - 任务运行/日志/步骤状态/终止
   - Finding/Evidence/报告
   - 审批处理
   - Audit 与 Policy Explain
   - 系统配置与标准协议中心

禁止：
- Web 不得直接启动工具
- Web 不得绕过 Core
- Web 不得重复实现 Policy 判断
- 不要做展示型大屏优先

验收：
- Web 可完成插件校验到报告查看完整流程
- CLI 与 Web 对同一 Task 得到一致的 plan 和 Policy 结果
- API 关键操作均有认证、授权、审计
- 任务日志断线重连后可继续查看
```

---
# 14. Codex 使用策略

## 14.1 工作循环

每一轮使用 Codex，都要求它按以下循环工作：

```text
读现有代码
→ 判断当前阶段是否满足前置条件
→ 提出实现计划
→ 修改代码
→ 增加测试
→ 运行验收命令
→ 输出变更说明
→ 停止，不做下一阶段
```

## 14.2 最重要的约束语句

```md
不要提前实现后续阶段。
不要为了演示方便绕过架构边界。
不要把具体工具逻辑写入 Core。
不要省略测试。
不要用 mock 掩盖真实执行链路。
不要生成任何真实攻击、利用、爆破、持久化或隐蔽绕过能力。
```

## 14.3 第一版正式验收闭环

```text
sentinelflow init
→ 放置示例插件
→ plugin validate
→ plugin install
→ tool list
→ tool run
→ 生成标准 Finding
→ 保存 Run/Result
→ 写入 Audit Event
→ report generate
```

## 14.4 第二版正式验收闭环

```text
编写 task.yaml
→ sentinelflow task plan task.yaml
→ 框架校验授权、策略、工具依赖
→ sentinelflow task run task.yaml
→ 按步骤执行工具
→ 步骤之间传递标准结果
→ 结果归一化
→ 保存任务日志和审计事件
→ 导出结果
```

---

# 15. 结论

SentinelFlow 的开发方式应当是：

```text
标准先行
→ Core 稳定
→ CLI 跑通
→ 插件接入
→ 结果归一
→ 审计留痕
→ 策略控制
→ 编排增强
→ API/Web 后置
```

不要把第一版做成“很多工具功能的集合”，而要做成“任何工具都能被可靠接入、受控执行、标准输出、审计追踪”的框架底座。

只有当 `Manifest → Registry → Adapter → Runtime → Normalizer → Store → Audit → Report` 这条链路稳定之后，SentinelFlow 才具备继续扩展为 Web 平台、插件生态和团队协同系统的基础。
