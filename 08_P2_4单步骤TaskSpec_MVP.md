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
