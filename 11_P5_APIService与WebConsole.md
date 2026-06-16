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
