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
