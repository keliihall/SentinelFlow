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
