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
