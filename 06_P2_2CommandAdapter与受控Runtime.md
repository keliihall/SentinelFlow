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
