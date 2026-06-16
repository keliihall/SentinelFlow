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
