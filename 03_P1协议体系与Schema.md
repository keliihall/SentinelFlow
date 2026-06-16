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
