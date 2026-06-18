# SentinelFlow 插件能力矩阵与建设规划

> 文档版本：V1.0  
> 适用项目：SentinelFlow 网络安全验证工具管理框架  
> 文档性质：产品规划 / 插件生态设计 / 开发参考  
> 适用阶段：v1.0-rc / P5.5 及后续 P6 规划  
> 核心定位：围绕授权资产验证场景，构建可治理、可审计、可扩展的安全验证插件生态。

---

## 1. 总体定位

SentinelFlow 不是一个单一安全扫描器，也不是攻击链自动化平台，而是一个面向授权安全验证场景的插件化管理框架。

它适合接入各种外部安全工具、情报 API、本地脚本、Docker 工具、HTTP 服务和结果导入器，并通过统一的标准体系进行治理：

- Tool Manifest
- Input Schema
- Output Schema
- Task Spec
- Finding / Evidence
- Policy
- Audit Event
- Report
- Plugin / Adapter Runtime

平台的核心目标是：

```text
统一接入
统一编排
统一执行
统一输出
统一归一化
统一审计
统一策略控制
统一报告
统一持续扩展
```

因此，插件建设不应围绕“堆扫描能力”，而应围绕“授权、可控、可审计、可报告”的安全验证流程展开。

---

## 2. 插件能力总览

SentinelFlow 可以支持的插件大致分为以下几类：

| 插件大类 | 核心作用 | 推荐优先级 |
|---|---|---|
| 资产发现类插件 | 发现域名、IP、端口、服务、证书、Web 入口 | 最高 |
| 情报聚合类插件 | 接入 FOFA、Shodan、Censys、crt.sh、云资产、CMDB | 最高 |
| 低影响验证类插件 | 探活、指纹、TLS、配置风险、基线检查 | 高 |
| 结果导入类插件 | 导入 Nessus、OpenVAS、ZAP、Nuclei、CSV/JSON 等结果 | 高 |
| 报告分析类插件 | 报告生成、结果去重、风险评分、资产画像 | 高 |
| 工单协同类插件 | 整改流转、CMDB 同步、工单系统对接 | 中 |
| 高风险验证类插件 | 漏洞验证、弱口令检测、深度指纹、PoC 验证 | 受控支持 |
| 靶场/实验类插件 | 漏洞复现、攻击链验证、红队模拟 | 后续/靶场限定 |

---

## 3. 资产发现类插件

资产发现类插件是 SentinelFlow 当前阶段最适合优先建设的插件方向。

### 3.1 子域名发现插件

推荐插件：

```text
subdomain-discovery-plus
```

能力包括：

- crt.sh 查询
- FOFA / Shodan / Censys 等外部情报源接入
- 本地缓存
- 被动 DNS 数据
- 字典枚举
- 泛解析检测
- 多源去重
- 置信度计算
- source_details 标记

建议能力类型：

```text
asset.subdomain.discovery
asset.subdomain
```

推荐模式：

```text
fixture
dry_run
passive_intel
active_dictionary
hybrid
```

---

### 3.2 DNS 解析插件

推荐插件：

```text
dns-resolve-plus
```

能力包括：

- A / AAAA / CNAME / MX / NS / TXT 查询
- 本地缓存
- 被动 DNS 情报
- public resolver 查询
- system resolver 查询
- authoritative trace
- 多 resolver 结果对比
- DNS 结果冲突标记
- 解析结果置信度计算

建议能力类型：

```text
asset.dns_resolve
```

推荐模式：

```text
fixture
dry_run
passive_intel
active
hybrid
```

---

### 3.3 HTTP 探活插件

推荐插件：

```text
http-probe-plus
```

能力包括：

- HTTP / HTTPS 探活
- 状态码
- 跳转链
- 页面标题
- Server Header
- Content-Type
- 响应大小
- TLS 基础信息
- 超时、限速、并发控制
- Web 入口识别

建议能力类型：

```text
asset.http_probe
```

推荐输出字段：

```text
url
status_code
title
server
content_type
content_length
redirect_chain
tls_enabled
source
confidence
```

---

### 3.4 端口暴露面验证插件

推荐插件：

```text
port-probe-plus
```

产品定位：

```text
端口暴露面多源验证插件
```

能力包括：

- FOFA 查询
- Shodan 查询
- local_cache
- fixture
- TCP Connect 探测
- SYN Probe 可配置
- external scanner 可配置
- 多源端口结果去重
- source_agreement 标记
- 冲突结果保留
- 置信度计算

建议能力类型：

```text
asset.port_probe
```

推荐模式：

```text
fixture
dry_run
passive_intel
active
hybrid
```

推荐 source_agreement：

```text
consistent
passive_only
active_only
conflict
stale_passive
unknown
```

---

### 3.5 服务识别插件

推荐插件：

```text
service-detect-plus
```

产品定位：

```text
服务识别多源验证插件
```

能力包括：

- 复用 port-probe-plus 的 FOFA/Shodan 服务字段
- local_cache
- passive_service_cache
- TCP Banner
- TLS Hello
- HTTP HEAD
- HTTP GET /
- safe 服务识别
- standard 服务识别
- deep 服务指纹可配置
- external_fingerprint 可配置
- 多源冲突标记
- 置信度计算

建议能力类型：

```text
asset.service_detect
```

推荐 detection_depth：

```text
fixture
passive
safe
standard
deep
external_fingerprint
```

---

### 3.6 Web 指纹识别插件

推荐插件：

```text
web-fingerprint-plus
```

能力包括：

- CMS 识别
- Web 框架识别
- JS 框架识别
- 中间件识别
- WAF/CDN 线索识别
- favicon hash
- header 指纹
- body 低影响特征
- 被动情报增强

建议能力类型：

```text
asset.web_fingerprint
```

注意：

- 不做漏洞验证。
- 不做路径爆破。
- 不做敏感文件探测。
- 默认只做低影响识别。

---

### 3.7 TLS / 证书检查插件

推荐插件：

```text
tls-certificate-check-plus
```

能力包括：

- 证书 Subject
- Issuer
- SAN
- 有效期
- 证书链
- 签名算法
- TLS 版本
- 证书透明日志关联
- 证书即将过期提醒
- 多域名证书关联资产发现

建议能力类型：

```text
asset.tls_certificate
```

---

### 3.8 IP / ASN / CDN 识别插件

推荐插件：

```text
ip-enrichment-plus
```

能力包括：

- IP 地理位置
- ASN
- ISP
- 云厂商识别
- CDN 识别
- WAF 线索
- 归属组织
- 公网 / 私网 / 保留地址分类

建议能力类型：

```text
asset.ip_enrichment
```

---

## 4. 情报聚合类插件

情报聚合类插件非常适合 SentinelFlow，因为这类插件风险较低、结果结构化程度高、适合多源比对。

### 4.1 FOFA 插件

推荐插件：

```text
fofa-import-plus
```

能力包括：

- 按域名查询
- 按 IP 查询
- 按组织查询
- 按证书查询
- 导入端口、服务、标题、Header、证书信息
- 结果去重
- 与主动探测结果对比

建议能力类型：

```text
data.import
asset.exposure_intel
```

安全要求：

- API Key 从环境变量或 Secret 配置读取。
- 不允许用户输入任意 FOFA 查询语句。
- 查询条件必须由授权目标自动构造。
- 不在日志、报告、审计中泄露密钥。

---

### 4.2 Shodan 插件

推荐插件：

```text
shodan-import-plus
```

能力包括：

- Host 查询
- 端口与服务信息导入
- Banner 摘要
- 证书信息导入
- 历史暴露信息
- 与主动探测结果比对

建议能力类型：

```text
data.import
asset.exposure_intel
```

---

### 4.3 Censys 插件

推荐插件：

```text
censys-import-plus
```

能力包括：

- Host 情报
- 证书情报
- 服务暴露信息
- 证书关联域名
- 公网资产搜索结果导入

建议能力类型：

```text
data.import
asset.exposure_intel
```

---

### 4.4 crt.sh 插件

推荐插件：

```text
crtsh-subdomain-plus
```

能力包括：

- 证书透明日志查询
- 子域名发现
- 通配符域名清洗
- 证书时间线
- 证书 SAN 资产提取

建议能力类型：

```text
asset.subdomain
asset.tls_certificate
```

---

### 4.5 云资产导入插件

推荐插件：

```text
cloud-asset-import-plus
```

可支持：

- 阿里云
- 腾讯云
- 华为云
- AWS
- Azure

能力包括：

- ECS / CVM / VM 实例
- 公网 IP
- 负载均衡
- 安全组
- 域名解析
- 对象存储暴露面
- 云 WAF / CDN 信息

建议能力类型：

```text
data.import
asset.cloud
```

---

### 4.6 CMDB 同步插件

推荐插件：

```text
cmdb-sync-plus
```

能力包括：

- 从 CMDB 导入资产
- 将 SentinelFlow 发现资产回写 CMDB
- 资产归属部门
- 业务系统映射
- 负责人映射
- 资产重要性标记

建议能力类型：

```text
data.import
data.export
asset.cmdb
```

---

## 5. 低影响验证类插件

低影响验证类插件适合在授权范围内常态化使用。

### 5.1 Web 基线检查插件

推荐插件：

```text
web-baseline-check-plus
```

能力包括：

- 安全 Header 检查
- HTTPS 强制检查
- HSTS 检查
- Cookie 安全属性检查
- 跨域配置检查
- 默认错误页检查
- 目录索引暴露检查

建议能力类型：

```text
risk.web_scan
risk.config_check
```

注意：

- 只做低影响请求。
- 不做路径爆破。
- 不做漏洞利用。

---

### 5.2 TLS 配置检查插件

推荐插件：

```text
tls-baseline-check-plus
```

能力包括：

- TLS 版本检查
- 弱加密套件检查
- 证书过期检查
- 证书链检查
- HSTS 检查
- SNI 检查

建议能力类型：

```text
risk.config_check
asset.tls_certificate
```

---

### 5.3 中间件配置检查插件

推荐插件：

```text
middleware-config-check-plus
```

能力包括：

- Nginx 安全配置
- Apache 安全配置
- Tomcat 默认页面
- Redis 暴露检查
- Elasticsearch 暴露检查
- 数据库端口暴露提示

建议能力类型：

```text
risk.config_check
risk.baseline_check
```

---

### 5.4 主机基线检查插件

推荐插件：

```text
host-baseline-check-plus
```

能力包括：

- SSH 配置
- 系统版本
- 开放端口
- 防火墙状态
- 安全补丁状态
- 用户与权限基线

适用场景：

- Agent 模式
- SSH 授权模式
- 导入已有巡检结果

建议能力类型：

```text
risk.baseline_check
```

---

## 6. 扫描器适配类插件

SentinelFlow 很适合把外部扫描器纳入统一治理，而不是自己重复造扫描器。

### 6.1 Nessus 导入插件

推荐插件：

```text
nessus-import-plus
```

能力包括：

- .nessus 文件导入
- 漏洞结果归一化
- CVE / CVSS 提取
- 主机和端口映射
- 证据解析
- 去重
- 报告融合

建议能力类型：

```text
data.import
risk.vuln_import
```

---

### 6.2 OpenVAS / Greenbone 导入插件

推荐插件：

```text
openvas-import-plus
```

能力包括：

- XML / CSV 结果导入
- 漏洞归一化
- 资产映射
- CVE 提取
- 严重性映射

建议能力类型：

```text
data.import
risk.vuln_import
```

---

### 6.3 Nuclei 适配插件

推荐插件：

```text
nuclei-adapter-plus
```

能力包括：

- 受控模板扫描
- 模板白名单
- 严格禁用高风险模板
- 结果归一化
- 证据结构化
- Policy 审批

建议能力类型：

```text
risk.web_scan
risk.vuln_verify
```

安全要求：

- 默认只允许 low / info 模板。
- medium 以上模板需要审批。
- 禁止 destructive / intrusive 模板默认运行。
- 模板目录必须白名单。

---

### 6.4 OWASP ZAP Baseline 插件

推荐插件：

```text
zap-baseline-plus
```

能力包括：

- ZAP baseline scan
- 被动扫描
- 低影响 Web 检测
- 报告导入
- 风险归一化

建议能力类型：

```text
risk.web_scan
```

---

### 6.5 AWVS / 商业扫描器适配插件

推荐插件：

```text
commercial-scanner-adapter-plus
```

能力包括：

- 调用商业扫描器 API
- 查询扫描任务
- 导入结果
- 结果归一化
- 风险去重
- 报告融合

建议能力类型：

```text
risk.web_scan
data.import
```

---

## 7. 报告与分析类插件

### 7.1 Markdown 报告插件

推荐插件：

```text
markdown-report-plus
```

能力包括：

- 按任务生成 Markdown 报告
- 按 Finding 类型分类
- 汇总统计
- 表格展示
- 审计摘要
- 错误与跳过项说明

建议能力类型：

```text
report.generate
```

---

### 7.2 HTML / PDF / Word 报告插件

推荐插件：

```text
formal-report-plus
```

能力包括：

- HTML 报告
- PDF 报告
- Word 报告
- 企业模板
- 客户交付版报告
- 管理摘要
- 技术详情
- 附录证据

建议能力类型：

```text
report.generate
```

---

### 7.3 风险评分插件

推荐插件：

```text
risk-score-plus
```

能力包括：

- 按资产评分
- 按服务评分
- 按端口评分
- 按漏洞评分
- 结合业务重要性
- 结合暴露面
- 结合多源置信度
- 输出优先级

建议能力类型：

```text
risk.score
```

---

### 7.4 资产画像插件

推荐插件：

```text
asset-profile-plus
```

能力包括：

- 域名—子域名—IP—端口—服务关系图
- 资产归属
- 业务系统映射
- 暴露面画像
- 服务分布
- 技术栈分析

建议能力类型：

```text
asset.profile
```

---

### 7.5 资产变更对比插件

推荐插件：

```text
asset-change-diff-plus
```

能力包括：

- 两次任务结果对比
- 新增子域名
- 消失子域名
- 新增 IP
- 新增开放端口
- 关闭端口
- 服务变化
- 证书变化
- 风险趋势

建议能力类型：

```text
asset.diff
```

---

## 8. 协同与工单类插件

### 8.1 工单系统插件

推荐插件：

```text
ticket-sync-plus
```

可对接：

- Jira
- 禅道
- TAPD
- 企业微信工单
- 飞书工单
- 自研工单系统

能力包括：

- Finding 转工单
- 整改状态同步
- 负责人分配
- SLA 跟踪
- 复测任务创建

建议能力类型：

```text
workflow.ticket
data.export
```

---

### 8.2 通知插件

推荐插件：

```text
notification-plus
```

可支持：

- 邮件
- 企业微信
- 钉钉
- 飞书
- Slack
- Webhook

能力包括：

- 任务完成通知
- 高风险发现通知
- 审批提醒
- 报告生成通知
- 失败告警

建议能力类型：

```text
workflow.notify
```

---

### 8.3 审批增强插件

推荐插件：

```text
approval-workflow-plus
```

能力包括：

- 高风险任务审批
- 多级审批
- 审批理由
- 审批过期
- 审批撤销
- 审批审计

建议能力类型：

```text
workflow.approval
```

---

## 9. 高风险验证类插件

高风险能力不是不能支持，而是必须受控支持。

### 9.1 漏洞验证插件

推荐插件：

```text
vuln-verify-plus
```

能力包括：

- 低影响 PoC 验证
- 只读型验证
- 证明型验证
- 靶场验证
- 结果证据化

建议能力类型：

```text
risk.vuln_verify
```

安全要求：

- 默认关闭。
- 必须授权。
- 必须审批。
- 必须限速。
- 必须审计。
- 必须记录证据。
- 不得默认运行破坏性 PoC。
- 生产环境只允许低影响验证。

---

### 9.2 弱口令风险检测插件

推荐插件：

```text
weak-password-check-plus
```

能力包括：

- 已授权账号口令检查
- 小规模验证
- 密码策略验证
- 默认口令检测

建议能力类型：

```text
risk.weak_password_check
```

安全要求：

- 默认关闭。
- 必须审批。
- 必须限定账号来源。
- 必须限定尝试次数。
- 必须限速。
- 必须锁定保护。
- 不得执行大规模爆破。

---

### 9.3 高级服务指纹插件

推荐插件：

```text
deep-fingerprint-plus
```

能力包括：

- 更深层协议握手
- 服务版本确认
- 产品识别
- 多协议组合判断

建议能力类型：

```text
asset.service_detect
```

安全要求：

- 默认关闭。
- 必须授权。
- 必须审批。
- 不得包含漏洞利用、畸形包、fuzzing、DoS。

---

## 10. 靶场与实验类插件

这类插件只建议用于 lab / 靶场，不建议进入默认生产工作流。

### 10.1 靶场 PoC 验证插件

推荐插件：

```text
lab-poc-verify-plus
```

能力包括：

- 靶场漏洞复现
- PoC 流程验证
- 漏洞教学演示
- 攻防演练环境验证

建议能力类型：

```text
lab.vuln_verify
```

---

### 10.2 红队模拟插件

推荐插件：

```text
redteam-simulation-plus
```

能力包括：

- 授权演练流程
- 攻击路径模拟
- 检测规则验证
- 蓝队响应验证

建议阶段：

```text
P7 或独立靶场版本
```

不建议放入 v1.0-rc 或常规生产插件市场。

---

## 11. 插件运行形态

SentinelFlow 可支持多种插件运行形态。

| 插件形态 | 说明 | 适用场景 |
|---|---|---|
| Command 插件 | 本地命令行执行 | Python runner、Go/Rust 工具 |
| Script 插件 | Python/Shell/Node 脚本 | 快速适配、轻量工具 |
| Docker 插件 | 容器化工具 | 隔离执行、安全工具封装 |
| HTTP API 插件 | 调用远程 API | FOFA、Shodan、商业扫描器 |
| File Import 插件 | 导入已有结果 | Nessus、CSV、JSON、XML |
| Remote Worker 插件 | 远程 Worker 执行 | 分布式任务 |
| Kubernetes Job 插件 | K8s 任务调度 | 云原生部署 |
| Commercial Scanner 插件 | 商业扫描器 API | AWVS、Qualys、Nessus |
| SIEM/SOC 插件 | 告警平台对接 | 安全运营 |
| CMDB/工单插件 | 资产和整改闭环 | 企业协作 |

---

## 12. 插件风险分级

建议插件能力按照风险等级进行治理。

| 风险等级 | 说明 | 默认策略 |
|---|---|---|
| info | 纯信息展示，不访问目标 | 默认允许 |
| low | 低影响，只读或被动情报 | 默认允许 |
| medium | 主动低影响验证 | 需要 allow_active_verify |
| high | 高风险验证，可能影响目标 | 需要审批 |
| critical | 仅限靶场或特殊授权 | 默认禁止 |

---

## 13. 插件影响类型

| 影响类型 | 说明 |
|---|---|
| read_only | 只读，不主动访问目标 |
| passive_intel | 被动情报查询 |
| low_impact | 低影响请求 |
| state_check | 状态检查 |
| active_verify | 主动验证 |
| credential_check | 凭据风险检测 |
| lab_only | 仅限靶场 |
| forbidden | 禁止在生产环境执行 |

---

## 14. 插件 Manifest 建议字段

每个插件都应通过 Manifest 声明自身能力边界。

建议字段包括：

```yaml
apiVersion: sentinelflow.io/v1alpha1
kind: Tool
metadata:
  name: example-plugin
  displayName: Example Plugin
  version: 1.0.0
  description: Example plugin description

spec:
  type: asset.example
  category: asset_discovery
  riskLevel: low

  capabilities:
    - id: asset.example
      name: Example Capability
      impact: read_only
      requiresApproval: false

  runtime:
    mode: command
    command: python runner/runner.py
    timeoutSeconds: 300

  input:
    schema: schemas/input.schema.json

  output:
    schema: schemas/output.schema.json
    format: jsonl
    parser: parser/parser.py

  controls:
    requiresAuthorization: true
    requiresApproval: false
    supportsRateLimit: true
    supportsConcurrencyLimit: true
    maxConcurrency: 5

  audit:
    recordInput: true
    recordOutputSummary: true
    recordRawOutput: false
    evidenceRequired: true
```

---

## 15. 插件输入标准建议

所有插件输入应包含：

```json
{
  "context": {
    "task_id": "task_xxx",
    "run_id": "run_xxx",
    "operator": "admin",
    "workspace": "default",
    "authorization_scope": "real:example"
  },
  "target": {
    "type": "domain",
    "value": "example.com",
    "metadata": {}
  },
  "options": {},
  "policy": {
    "allow_active_verify": false,
    "allow_high_risk": false
  }
}
```

关键要求：

- 必须有 context。
- 必须有 authorization_scope。
- 必须有 target。
- 必须有 options。
- 必须有 policy。
- 高风险能力必须显式声明。
- 未授权目标不得执行。

---

## 16. 插件输出标准建议

所有插件输出应转换为标准 Finding / Evidence。

建议输出结构：

```json
{
  "apiVersion": "sentinelflow.io/v1alpha1",
  "kind": "Finding",
  "metadata": {
    "task_id": "task_xxx",
    "run_id": "run_xxx",
    "tool": "example-plugin",
    "created_at": "2026-01-01T00:00:00Z"
  },
  "target": {
    "type": "domain",
    "value": "example.com"
  },
  "finding": {
    "type": "asset.example",
    "severity": "info",
    "title": "Example finding",
    "confidence": 0.8
  },
  "evidence": {
    "summary": "Structured evidence summary.",
    "items": []
  },
  "extensions": {}
}
```

---

## 17. 推荐插件建设路线

### 17.1 P5.5 / v1.0-rc 优先插件

| 插件 | 优先级 | 说明 |
|---|---|---|
| subdomain-discovery-plus | 最高 | 子域名发现 |
| dns-resolve-plus | 最高 | DNS 解析与情报 |
| port-probe-plus | 最高 | 端口暴露面验证 |
| service-detect-plus | 最高 | 服务识别 |
| http-probe-plus | 高 | HTTP 探活 |
| web-fingerprint-plus | 高 | Web 指纹 |
| tls-certificate-check-plus | 高 | TLS / 证书检查 |
| fofa-import-plus | 高 | 外部情报导入 |
| shodan-import-plus | 高 | 外部情报导入 |
| markdown-report-plus | 高 | 报告增强 |

---

### 17.2 P6 插件

| 插件 | 价值 |
|---|---|
| nessus-import-plus | 导入商业扫描器结果 |
| openvas-import-plus | 导入开源扫描器结果 |
| nuclei-adapter-plus | 受控模板扫描 |
| zap-baseline-plus | Web Baseline 检查 |
| cloud-asset-import-plus | 云资产同步 |
| cmdb-sync-plus | 资产台账同步 |
| risk-score-plus | 风险评分 |
| asset-change-diff-plus | 资产变更对比 |
| ticket-sync-plus | 整改工单闭环 |
| notification-plus | 通知告警 |

---

### 17.3 后续高级插件

| 插件 | 注意事项 |
|---|---|
| vuln-verify-plus | 必须审批、限速、审计 |
| weak-password-check-plus | 必须强审批，默认禁用 |
| deep-fingerprint-plus | 只允许授权或靶场 |
| lab-poc-verify-plus | 仅限靶场 |
| redteam-simulation-plus | 不建议放入 v1.0-rc |
| distributed-worker-adapter | P6 后支持分布式 |

---

## 18. 插件市场分级建议

后续如果建设插件市场，建议插件质量分为：

| 等级 | 说明 |
|---|---|
| experimental | 实验插件，不建议生产使用 |
| community | 社区插件，需自行评估 |
| verified | 已通过框架校验 |
| trusted | 受信插件，可在生产授权范围内使用 |
| restricted | 高风险插件，需审批和隔离 |

---

## 19. 不建议默认开放的插件能力

以下能力不建议在 v1.0-rc 默认开放：

```text
真实漏洞利用
大规模弱口令爆破
凭据攻击
持久化
隐蔽扫描
绕过检测
攻击链自动化
横向移动
DoS / 压测型攻击
畸形包 fuzzing
未授权资产扫描
```

如果未来支持，也必须满足：

```text
默认关闭
显式授权
Policy Explain
审批通过
限速
隔离
审计
靶场优先
可追责
```

---

## 20. 推荐最终插件生态形态

SentinelFlow 的插件生态建议形成以下闭环：

```text
资产发现
  ↓
情报聚合
  ↓
低影响验证
  ↓
风险归一
  ↓
报告生成
  ↓
整改协同
  ↓
复测验证
  ↓
审计留痕
```

核心插件链路建议：

```text
subdomain-discovery-plus
  ↓
dns-resolve-plus
  ↓
port-probe-plus
  ↓
service-detect-plus
  ↓
web-fingerprint-plus
  ↓
tls-certificate-check-plus
  ↓
risk-score-plus
  ↓
markdown-report-plus
```

---

## 21. 总结

SentinelFlow 最适合建设的插件生态不是“攻击工具集合”，而是：

```text
资产发现插件
情报聚合插件
低影响验证插件
结果导入插件
风险分析插件
报告生成插件
整改协同插件
审计治理插件
```

当前阶段最优先建设：

```text
子域名发现
DNS 解析
端口暴露面验证
服务识别
HTTP 探活
Web 指纹
TLS 证书检查
FOFA / Shodan 情报导入
报告增强
```

高风险能力可以作为受控插件接入，但必须默认关闭，并通过授权、审批、限速、隔离、审计和报告机制进行治理。

最终目标是形成一个可持续扩展的安全验证插件生态，使 SentinelFlow 成为：

> 面向授权安全评估场景的插件化、安全治理化、可审计、可报告的外部安全验证工具管理框架。
