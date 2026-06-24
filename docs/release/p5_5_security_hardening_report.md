# SentinelFlow P5.5 Security Hardening Report

Generated: 2026-06-24T05:44:25Z

Command: `tests/e2e/p5_5_security/run.sh`
Workspace: `/var/folders/46/j153v48s4dqg3wg85sg3g4mw0000gn/T/sentinelflow-p55-security.n2xqt471/.sentinelflow`

## Scope

This report covers authorization, policy denial, audit, sensitive information protection, plugin isolation, path safety, command injection, output limits, abnormal plugin exits, parser invalid output, API permission boundaries, and Web/API bypass attempts.

All tests use local safe fixtures only. No public targets, real credentials, real secrets, scanner behavior, exploitation, brute force, stealth probing, persistence, authentication bypass, or attack-chain automation are used.

## Result Summary

| Category | Expected Security Behavior | Result | Evidence |
| --- | --- | --- | --- |
| login audit success | 成功登录写入 Audit | pass | api.session.login succeeded |
| login audit denied | 失败登录写入 denied Audit | pass | api.session.login denied |
| 未授权目标 | task run 被拒绝且有 policy.denied | pass | status=403 code=AuthorizationDenied |
| 高风险未审批 | 未审批 high risk 被拒绝 | pass | status=403 code=AuthorizationDenied |
| 审批过期 | expired approval 不得执行 | pass | status=403 code=AuthorizationDenied |
| 用户角色不足 | viewer 不能安装插件且拒绝被审计 | pass | status=403 |
| 越权访问他人任务 | 无凭据读任务被拒绝且审计 | pass | status=401 |
| 越权查看报告 | 无凭据读报告被拒绝且审计 | pass | status=401 |
| 越权查看审计 | 无凭据读审计被拒绝且审计 | pass | status=401 |
| API 直接调用绕过 Web | API 直接恶意请求仍被 Policy 拒绝 | pass | status=403 |
| Web 修改请求绕过前端限制 | viewer 伪造 Web task run 被 API 拒绝 | pass | status=403 |
| 时间窗口不匹配 | 当前时间不在窗口内时拒绝 | pass | status=403 |
| 目标边界绕过-相似域 | evilexample.com 不匹配 domain:example.com | pass | {"allowed": false, "reasons": ["target is outside the authorization boundary: evilexample.com"], "retention": {"days": 30, "retainEvidence": true}} |
| 目标边界-子域允许 | *.example.com 只允许真实子域 | pass | {"allowed": true, "reasons": [], "retention": {"days": 30, "retainEvidence": true}} |
| 目标边界-IP/CIDR | CIDR 外 IP 被拒绝 | pass | {"allowed": false, "reasons": ["target is outside the authorization boundary: 198.51.101.1"], "retention": {"days": 30, "retainEvidence": true}} |
| 路径穿越 | 非插件/穿越路径无法安装 | pass | status=500 |
| 命令注入 | 输入中的 shell 片段按普通字符串处理 | pass | status=200 marker=False |
| Secret 写入日志/报告 | 报告不包含 token/secret/credential 明文 | pass | report redacted |
| 原始输出超限 | Command Adapter contract 覆盖 OutputLimit；E2E 使用受控失败任务 | pass | covered by crates/sentinelflow-adapter-command/tests/runtime_contract.rs |
| 环境变量泄漏 | Command Adapter 只继承 Manifest allowlist 环境变量 | pass | covered by environment_is_allowlisted_and_arguments_are_not_shell_interpreted |
| 插件异常退出 | 异常退出返回 RuntimeError 并记录 tool.run.failed | pass | status=400 |
| Parser 恶意输出 | 非法 Parser 输出被 Schema/Normalizer 拒绝 | pass | status=400 code=SchemaValidationFailed |

## Policy Coverage Review

| Execution Point | Current Coverage |
| --- | --- |
| task create / validate | Schema and semantic validation before persistence or execution. |
| task plan | DAG validation, no execution. |
| task run | Preflight Policy rejects unauthorized targets, high risk without approval, expired approvals, and invalid time windows. |
| step start | Each step re-enters Policy and Adapter authorization before prepare/execute. |
| output persist | Only Parser and Normalizer outputs are persisted; raw stdout/stderr are not persisted. |
| report export/generate | Reports read normalized artifacts and redact sensitive-looking fields during rendering. |

## Audit Coverage Review

| Action | Coverage |
| --- | --- |
| login | `api.session.login` records succeeded and denied attempts. |
| plugin validate/install | API and CLI plugin actions record audit events; denied API install attempts are audited. |
| task plan/run/cancel | API plan/run and core cancellation record audit; preflight Policy denial records `policy.denied`. |
| approval request/approve/reject/expire | Approval endpoints record audit events. |
| policy denied | Preflight and step-level denials record `policy.denied`. |
| report generate/export | Report generation records `api.reports.generate` and `report.generated`; CLI export is covered by normalized result path. |

## Release Decision

- Failed checks: `0`
- Result: `pass`
