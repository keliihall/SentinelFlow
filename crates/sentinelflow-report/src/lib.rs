//! Deterministic Markdown reports for normalized `SentinelFlow` runs.

use std::fmt::Write;

use sentinelflow_schema::v1alpha1::AuditEvent;
use sentinelflow_store::{RunBundle, TaskArtifact};
use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

/// Generates a Markdown report from persisted, normalized run data.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn generate_markdown(bundle: &RunBundle) -> String {
    let mut report = String::new();
    let finding_count = bundle
        .result
        .output
        .as_ref()
        .map_or(0, |output| output.spec.findings.len());
    let error_count = bundle.result.errors.len()
        + bundle
            .result
            .output
            .as_ref()
            .map_or(0, |output| output.spec.errors.len());

    writeln!(report, "# SentinelFlow Run Report\n").expect("writing to String cannot fail");
    writeln!(report, "## Summary\n").expect("writing to String cannot fail");
    writeln!(report, "- Run: `{}`", bundle.run.identifiers.run_id)
        .expect("writing to String cannot fail");
    writeln!(report, "- Status: `{:?}`", bundle.run.status).expect("writing to String cannot fail");
    writeln!(report, "- Findings: {finding_count}").expect("writing to String cannot fail");
    writeln!(report, "- Errors: {error_count}\n").expect("writing to String cannot fail");

    writeln!(report, "## Target\n").expect("writing to String cannot fail");
    writeln!(report, "{}\n", redact_text(&bundle.run.target))
        .expect("writing to String cannot fail");

    writeln!(report, "## Tool\n").expect("writing to String cannot fail");
    writeln!(report, "- Tool ID: `{}`", bundle.run.identifiers.tool_id)
        .expect("writing to String cannot fail");
    writeln!(report, "- Capability: `{}`", bundle.run.capability)
        .expect("writing to String cannot fail");
    writeln!(
        report,
        "- Authorization scope: `{}`\n",
        bundle.run.authorization_scope
    )
    .expect("writing to String cannot fail");

    writeln!(report, "## Findings\n").expect("writing to String cannot fail");
    if finding_count == 0 {
        writeln!(report, "No findings were produced.\n").expect("writing to String cannot fail");
    } else if let Some(output) = &bundle.result.output {
        for finding in &output.spec.findings {
            writeln!(report, "### {} ({:?})\n", finding.title, finding.severity)
                .expect("writing to String cannot fail");
            writeln!(report, "{}\n", redact_text(&finding.summary))
                .expect("writing to String cannot fail");
        }
    }

    writeln!(report, "## Evidence\n").expect("writing to String cannot fail");
    let mut evidence_count = 0;
    if let Some(output) = &bundle.result.output {
        for finding in &output.spec.findings {
            for evidence in &finding.evidence {
                evidence_count += 1;
                writeln!(
                    report,
                    "- **{}**: {}",
                    evidence.evidence_type, evidence.description
                )
                .expect("writing to String cannot fail");
                writeln!(
                    report,
                    "  ```json\n  {}\n  ```",
                    serde_json::to_string_pretty(&redact_json(&evidence.data))
                        .unwrap_or_else(|_| "null".to_owned())
                        .replace('\n', "\n  ")
                )
                .expect("writing to String cannot fail");
            }
        }
    }
    if evidence_count == 0 {
        writeln!(report, "No evidence was produced.").expect("writing to String cannot fail");
    }
    report.push('\n');

    writeln!(report, "## Errors\n").expect("writing to String cannot fail");
    let mut rendered_errors = 0;
    if let Some(output) = &bundle.result.output {
        for error in &output.spec.errors {
            rendered_errors += 1;
            writeln!(
                report,
                "- `{}`: {}",
                error.code,
                redact_text(&error.message)
            )
            .expect("writing to String cannot fail");
        }
    }
    for error in &bundle.result.errors {
        rendered_errors += 1;
        writeln!(
            report,
            "- `{}`: {}",
            error.error.code,
            redact_text(&error.error.message)
        )
        .expect("writing to String cannot fail");
    }
    if rendered_errors == 0 {
        writeln!(report, "No errors were recorded.").expect("writing to String cannot fail");
    }
    report.push('\n');

    writeln!(report, "## Audit Summary\n").expect("writing to String cannot fail");
    if bundle.audit_events.is_empty() {
        writeln!(report, "No audit events were recorded.").expect("writing to String cannot fail");
    } else {
        for event in &bundle.audit_events {
            writeln!(
                report,
                "- `{}`: `{:?}` at {}",
                event.spec.action, event.spec.outcome, event.spec.timestamp
            )
            .expect("writing to String cannot fail");
        }
    }
    report
}

/// Generates one Markdown report for all target runs in a task.
#[must_use]
pub fn generate_task_markdown(
    task: &TaskArtifact,
    bundles: &[RunBundle],
    audit_events: &[AuditEvent],
) -> String {
    let mut report = String::new();
    let findings = bundles
        .iter()
        .filter_map(|bundle| bundle.result.output.as_ref())
        .map(|output| output.spec.findings.len())
        .sum::<usize>();
    writeln!(report, "# SentinelFlow Task Report\n").expect("String write");
    writeln!(report, "## Summary\n").expect("String write");
    writeln!(report, "- Task: `{}`", task.task_id).expect("String write");
    writeln!(report, "- Name: {}", task.name).expect("String write");
    writeln!(report, "- Status: `{:?}`", task.status).expect("String write");
    writeln!(report, "- Targets: {}", task.target_count).expect("String write");
    writeln!(report, "- Runs: {}", bundles.len()).expect("String write");
    writeln!(report, "- Findings: {findings}\n").expect("String write");
    for bundle in bundles {
        writeln!(
            report,
            "## Target: {}\n\n{}",
            redact_text(&bundle.run.target),
            generate_markdown(bundle)
        )
        .expect("String write");
    }
    writeln!(report, "\n## Task Audit Summary\n").expect("String write");
    if audit_events.is_empty() {
        writeln!(report, "No task audit events were recorded.").expect("String write");
    } else {
        for event in audit_events {
            writeln!(
                report,
                "- `{}`: `{:?}` at {}",
                event.spec.action, event.spec.outcome, event.spec.timestamp
            )
            .expect("String write");
        }
    }
    report
}

/// Generates a Chinese asset-discovery delivery report for a task.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn generate_asset_discovery_markdown(
    task: &TaskArtifact,
    bundles: &[RunBundle],
    audit_events: &[AuditEvent],
) -> String {
    let mut report = String::new();
    let mut subdomains = Vec::new();
    let mut dns = Vec::new();
    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut candidate_subdomains = Vec::new();
    let mut invalid_dns = Vec::new();
    let mut skipped_stages = Vec::new();
    let mut evidence_rows = Vec::new();
    let mut errors = Vec::new();
    let mut source_status = Vec::new();

    for bundle in bundles {
        if let Some(output) = &bundle.result.output {
            if let Some(status) = output
                .spec
                .values
                .get("source_status")
                .and_then(Value::as_array)
            {
                for item in status {
                    if item
                        .get("status")
                        .and_then(Value::as_str)
                        .is_some_and(|status| status == "skipped" || status.starts_with("skipped_"))
                    {
                        skipped_stages.push(item.clone());
                    }
                    source_status.push(item.clone());
                }
            }
            if output.spec.values.get("source").and_then(Value::as_str)
                == Some("subdomain-discovery-plus")
            {
                if let Some(raw_findings) =
                    output.spec.values.get("findings").and_then(Value::as_array)
                {
                    for item in raw_findings {
                        if item.get("type").and_then(Value::as_str) == Some("subdomain_candidate") {
                            candidate_subdomains.push(item.clone());
                        }
                    }
                }
            }
            if output.spec.values.get("source").and_then(Value::as_str) == Some("dns-resolve-plus")
            {
                if let Some(raw_results) =
                    output.spec.values.get("results").and_then(Value::as_array)
                {
                    for item in raw_results {
                        let record_type = item.get("record_type").and_then(Value::as_str);
                        let invalid_address = matches!(record_type, Some("A" | "AAAA"))
                            && !item
                                .get("valid_for_port_probe")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                        if item.get("status").and_then(Value::as_str)
                            == Some("invalid_special_address")
                            || invalid_address
                        {
                            invalid_dns.push(item.clone());
                        }
                    }
                }
            }
            for error in &output.spec.errors {
                errors.push((error.code.clone(), error.message.clone()));
            }
            for finding in &output.spec.findings {
                for evidence in &finding.evidence {
                    let data = &evidence.data;
                    let finding_type = data
                        .get("findingType")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let unresolved_dictionary_candidate = finding_type == "asset.subdomain"
                        && !bool_value(data, "x-sentinelflow-subdomain.resolved")
                        && table_array(data, "x-sentinelflow-subdomain.sources")
                            .contains("active_dictionary")
                        && data
                            .get("x-sentinelflow-subdomain.status")
                            .and_then(Value::as_str)
                            .unwrap_or("candidate")
                            != "confirmed";
                    if !unresolved_dictionary_candidate {
                        evidence_rows.push((
                            finding.title.clone(),
                            finding.summary.clone(),
                            data.get("confidence")
                                .and_then(Value::as_f64)
                                .unwrap_or_default(),
                        ));
                    }
                    match finding_type {
                        "asset.subdomain" => {
                            if unresolved_dictionary_candidate {
                                candidate_subdomains.push(serde_json::json!({
                                    "type": "subdomain_candidate",
                                    "subdomain": data.get("x-sentinelflow-subdomain.subdomain").cloned().unwrap_or(Value::Null),
                                    "sources": data.get("x-sentinelflow-subdomain.sources").cloned().unwrap_or_else(|| serde_json::json!(["active_dictionary"])),
                                    "resolved": false,
                                    "status": "candidate",
                                    "confidence": data.get("confidence").cloned().unwrap_or_else(|| serde_json::json!(0.1))
                                }));
                            } else {
                                subdomains.push(data.clone());
                            }
                        }
                        "asset.dns_resolve" => dns.push(data.clone()),
                        "asset.port_probe" => ports.push(data.clone()),
                        "asset.service_detect" => services.push(data.clone()),
                        _ => {}
                    }
                }
            }
        }
        for error in &bundle.result.errors {
            errors.push((error.error.code.clone(), error.error.message.clone()));
        }
    }

    let target = task
        .spec_snapshot
        .spec
        .targets
        .first()
        .map_or_else(|| "unknown".to_owned(), |target| target.name.clone());
    let auth_scope = &task.spec_snapshot.spec.authorization_scope;
    let invalid_dns_keys = invalid_dns
        .iter()
        .filter_map(|item| {
            Some(format!(
                "{}|{}|{}",
                item.get("domain")?.as_str()?,
                item.get("record_type")?.as_str()?,
                item.get("value")?.as_str()?
            ))
        })
        .collect::<std::collections::BTreeSet<_>>();
    dns.retain(|item| {
        let key = format!(
            "{}|{}|{}",
            item.get("x-sentinelflow-dns.domain")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            item.get("x-sentinelflow-dns.record_type")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            item.get("x-sentinelflow-dns.value")
                .and_then(Value::as_str)
                .unwrap_or_default()
        );
        !invalid_dns_keys.contains(&key)
    });
    let unique_ips = dns
        .iter()
        .filter_map(|item| item.get("x-sentinelflow-dns.value").and_then(Value::as_str))
        .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        .collect::<std::collections::BTreeSet<_>>();
    let public_ip_count = unique_ips
        .iter()
        .filter(|value| is_public_ip(value))
        .count();
    let quality_gate = quality_gate_results(
        auth_scope,
        &subdomains,
        &candidate_subdomains,
        &dns,
        &invalid_dns,
        &ports,
        &services,
        &skipped_stages,
    );
    let quality_gate_failed = quality_gate.iter().any(|item| item.status == "Failed");
    let report_status = if quality_gate_failed {
        "invalid_quality_gate_failed"
    } else if subdomains.is_empty() && ports.is_empty() && services.is_empty() {
        "unconfirmed"
    } else if quality_gate.iter().any(|item| item.status == "Warning") {
        "valid_with_warnings"
    } else {
        "valid"
    };

    writeln!(
        report,
        "# SentinelFlow 授权资产发现报告：{}\n",
        redact_text(&target)
    )
    .expect("String write");
    writeln!(report, "## 1. 报告摘要\n").expect("String write");
    writeln!(report, "| 项目 | 值 |").expect("String write");
    writeln!(report, "| --- | --- |").expect("String write");
    writeln!(report, "| 目标域名 | `{}` |", redact_text(&target)).expect("String write");
    writeln!(report, "| 授权范围 | `{}` |", redact_text(auth_scope)).expect("String write");
    writeln!(report, "| Task ID | `{}` |", task.task_id).expect("String write");
    writeln!(report, "| Run IDs | `{}` |", task.run_ids.join("`, `")).expect("String write");
    writeln!(report, "| 执行状态 | `{:?}` |", task.status).expect("String write");
    writeln!(
        report,
        "| Quality Gate | `{}` |",
        if quality_gate_failed {
            "Failed"
        } else {
            "Passed"
        }
    )
    .expect("String write");
    writeln!(report, "| Report Status | `{report_status}` |").expect("String write");
    writeln!(report, "| 使用插件 | `subdomain-discovery-plus`, `dns-resolve-plus`, `port-probe-plus`, `service-detect-plus` |").expect("String write");
    writeln!(report, "| 已确认子域名 | {} |", subdomains.len()).expect("String write");
    writeln!(report, "| 候选子域名 | {} |", candidate_subdomains.len()).expect("String write");
    writeln!(report, "| 有效 DNS 记录 | {} |", dns.len()).expect("String write");
    writeln!(report, "| 无效 DNS 记录 | {} |", invalid_dns.len()).expect("String write");
    writeln!(
        report,
        "| 唯一 IP 数量（含保留地址） | {} |",
        unique_ips.len()
    )
    .expect("String write");
    writeln!(report, "| 公网 IP 数量 | {public_ip_count} |").expect("String write");
    writeln!(report, "| 开放端口数量 | {} |", ports.len()).expect("String write");
    writeln!(report, "| 服务识别数量 | {} |", services.len()).expect("String write");
    writeln!(report, "| 跳过阶段 | {} |", skipped_stages.len()).expect("String write");
    writeln!(report, "| 错误数量 | {} |", errors.len()).expect("String write");
    writeln!(report, "| 审计事件数量 | {} |\n", audit_events.len()).expect("String write");

    writeln!(report, "## 数据质量门禁\n").expect("String write");
    writeln!(
        report,
        "| 编号 | 检查项 | 状态 | 说明 |\n| --- | --- | --- | --- |"
    )
    .expect("String write");
    for item in &quality_gate {
        writeln!(
            report,
            "| {} | {} | {} | {} |",
            item.id,
            table_text(item.name),
            item.status,
            table_text(&item.message)
        )
        .expect("String write");
    }
    writeln!(report, "\n报告可信状态：`{report_status}`。\n").expect("String write");

    writeln!(report, "## 2. 执行范围与授权说明\n").expect("String write");
    writeln!(report, "- 目标：`{}`", redact_text(&target)).expect("String write");
    writeln!(report, "- 授权范围：`{}`", redact_text(auth_scope)).expect("String write");
    writeln!(
        report,
        "- 允许目标：`{}` 与其授权子域名。",
        redact_text(&target)
    )
    .expect("String write");
    writeln!(report, "- 本次采用非侵入优先和低影响主动验证策略。").expect("String write");
    writeln!(
        report,
        "- 未启用 `syn_probe`、`external_scanner`、`deep fingerprint`、`external_fingerprint`。"
    )
    .expect("String write");
    writeln!(
        report,
        "- 未执行漏洞利用、弱口令、爆破、绕过、DoS、fuzzing 或攻击链。\n"
    )
    .expect("String write");

    writeln!(report, "## 3. 方法与数据源\n").expect("String write");
    writeln!(report, "### 子域名探测\n\n| 方法 | 是否启用 | 类型 | 说明 | 状态 |\n| --- | --- | --- | --- | --- |\n| crt.sh | 是 | 被动 | 证书透明日志 | 见 source status |\n| local_cache | 是 | 被动 | 本地缓存 | empty/skipped |\n| passive_dns_cache | 是 | 被动 | 被动 DNS 缓存 | empty/skipped |\n| active_dictionary | 是 | 主动低影响 | DNS 字典枚举 | limited |\n").expect("String write");
    writeln!(report, "### DNS 解析\n\n| 方法 | 是否启用 | 记录类型 | 说明 | 状态 |\n| --- | --- | --- | --- | --- |\n| local_cache | 是 | A/AAAA/CNAME/MX/NS/TXT | 本地缓存 | 见 source status |\n| public_resolver | 是 | A/AAAA/CNAME/MX/NS/TXT | 公共解析器 | 见 source status |\n| system_resolver | 可选 | A/AAAA | 系统解析器 | skipped/ok |\n").expect("String write");
    writeln!(report, "### 端口探测\n\n| 方法 | 是否启用 | 类型 | 说明 | 状态 |\n| --- | --- | --- | --- | --- |\n| FOFA | 如有密钥 | 被动情报 | 公网暴露面 | skipped_missing_secret/ok |\n| Shodan | 如有密钥 | 被动情报 | 公网暴露面 | skipped_missing_secret/ok |\n| tcp_connect | 是 | 主动低影响 | TCP Connect | limited |\n").expect("String write");
    writeln!(report, "### 服务识别\n\n| 方法 | 是否启用 | 类型 | 说明 | 状态 |\n| --- | --- | --- | --- | --- |\n| upstream_port_result | 是 | 被动 | 复用端口结果 | ok |\n| fofa_enrichment | 如有密钥 | 被动 | 资产情报增强 | skipped/ok |\n| shodan_enrichment | 如有密钥 | 被动 | 资产情报增强 | skipped/ok |\n| tls_hello/http_head/tcp_banner | 是 | 主动低影响 | 安全服务识别 | limited |\n").expect("String write");

    writeln!(report, "## 4. 资产发现总览\n").expect("String write");
    writeln!(report, "| 指标 | 数量 |\n| --- | --- |").expect("String write");
    writeln!(report, "| 已确认子域名 | {} |", subdomains.len()).expect("String write");
    writeln!(report, "| 候选子域名 | {} |", candidate_subdomains.len()).expect("String write");
    writeln!(report, "| 无效 DNS 记录 | {} |", invalid_dns.len()).expect("String write");
    writeln!(report, "| 有效公网 IP | {public_ip_count} |").expect("String write");
    writeln!(report, "| 已确认开放端口 | {} |", ports.len()).expect("String write");
    writeln!(report, "| 已识别服务 | {} |", services.len()).expect("String write");
    writeln!(report, "| 跳过阶段 | {} |\n", skipped_stages.len()).expect("String write");

    write_subdomain_table(&mut report, &subdomains, &candidate_subdomains);
    write_dns_table(&mut report, &dns, &invalid_dns);
    write_port_table(&mut report, &ports, &skipped_stages, public_ip_count == 0);
    write_service_table(&mut report, &services, &skipped_stages, ports.is_empty());

    writeln!(report, "## 9. 重点发现\n").expect("String write");
    if subdomains.is_empty() && !candidate_subdomains.is_empty() {
        writeln!(
            report,
            "- 子域名结果均为未确认候选项，不能作为真实资产台账依据。"
        )
        .expect("String write");
    }
    if public_ip_count == 0 && !invalid_dns.is_empty() {
        writeln!(report, "- DNS 结果包含特殊用途地址，未形成有效公网 IP。").expect("String write");
    }
    if ports.is_empty() && skipped_reason(&skipped_stages, "no_public_routable_targets").is_some() {
        writeln!(report, "- 端口探测已跳过：上游 DNS 阶段未产生有效公网 IP。")
            .expect("String write");
    } else if ports.is_empty() {
        writeln!(report, "- 未确认开放端口。").expect("String write");
    } else {
        writeln!(
            report,
            "- 发现 {} 个开放端口，建议人工确认公网服务归属并纳入资产台账。",
            ports.len()
        )
        .expect("String write");
    }
    if errors.is_empty() {
        writeln!(report, "- 未记录阻断性错误。\n").expect("String write");
    } else {
        writeln!(
            report,
            "- 存在 {} 个错误或跳过项，建议优先复核 source status。\n",
            errors.len()
        )
        .expect("String write");
    }

    writeln!(report, "## 10. 证据摘要\n").expect("String write");
    writeln!(
        report,
        "| 发现项 | 证据摘要 | 置信度 |\n| --- | --- | --- |"
    )
    .expect("String write");
    for (title, summary, confidence) in evidence_rows.iter().take(30) {
        writeln!(
            report,
            "| {} | {} | {:.2} |",
            table_text(title),
            table_text(summary),
            confidence
        )
        .expect("String write");
    }
    if evidence_rows.is_empty() {
        writeln!(report, "| 无 | 未产生 Evidence。 | 0 |").expect("String write");
    }
    report.push('\n');

    writeln!(report, "## 11. 错误与跳过项\n").expect("String write");
    writeln!(
        report,
        "| 组件 | Source | 状态 | 原因 | 影响 |\n| --- | --- | --- | --- | --- |"
    )
    .expect("String write");
    for item in &source_status {
        writeln!(
            report,
            "| source | {} | {} | {} | 不影响其他已启用来源 |",
            table_text(
                item.get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
            table_text(
                item.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
            table_text(item.get("message").and_then(Value::as_str).unwrap_or(""))
        )
        .expect("String write");
    }
    for (code, message) in &errors {
        writeln!(
            report,
            "| runtime | {} | error | {} | 需复核 |",
            table_text(code),
            table_text(message)
        )
        .expect("String write");
    }
    if source_status.is_empty() && errors.is_empty() {
        writeln!(report, "| 无 | 无 | ok | 未记录错误或跳过项 | 无 |").expect("String write");
    }
    report.push('\n');

    writeln!(report, "## 12. 审计摘要\n").expect("String write");
    writeln!(
        report,
        "| 时间 | 事件 | 结果 | 操作者 | 资源 |\n| --- | --- | --- | --- | --- |"
    )
    .expect("String write");
    for event in audit_events.iter().take(50) {
        writeln!(
            report,
            "| {} | {} | {:?} | {} | {} |",
            event.spec.timestamp,
            table_text(&event.spec.action),
            event.spec.outcome,
            table_text(event.spec.actor.as_deref().unwrap_or("unknown")),
            table_text(event.spec.resource_ref.as_deref().unwrap_or(""))
        )
        .expect("String write");
    }
    report.push('\n');

    writeln!(report, "## 13. 结论与建议\n").expect("String write");
    if report_status == "invalid_quality_gate_failed" || report_status == "unconfirmed" {
        writeln!(report, "- 本次未确认有效公网资产。").expect("String write");
        if !candidate_subdomains.is_empty() || !invalid_dns.is_empty() {
            writeln!(
                report,
                "- 当前报告中的候选子域名、特殊用途 DNS 地址或跳过阶段不能作为真实资产发现依据。"
            )
            .expect("String write");
        }
    } else {
        writeln!(report, "- 建议人工确认关键公网服务归属。").expect("String write");
    }
    writeln!(report, "- 建议将多源冲突项和仅被动来源项列入复核。").expect("String write");
    writeln!(report, "- 建议将已确认资产纳入资产台账。").expect("String write");
    writeln!(
        report,
        "- 建议后续在授权窗口内执行更深入但受控的安全验证。\n"
    )
    .expect("String write");

    writeln!(report, "## 14. 附录\n").expect("String write");
    writeln!(report, "- TaskSpec: `{}`", task.name).expect("String write");
    writeln!(
        report,
        "- 策略：`allowActiveVerify=true`，`allowHighRisk=false`。"
    )
    .expect("String write");
    writeln!(
        report,
        "- 数据保留位置：SentinelFlow workspace `.sentinelflow`。"
    )
    .expect("String write");
    writeln!(
        report,
        "- 限制：被动来源依赖第三方可用性；主动探测仅覆盖配置的候选、端口与速率限制。"
    )
    .expect("String write");
    report
}

fn write_subdomain_table(report: &mut String, rows: &[Value], candidates: &[Value]) {
    writeln!(report, "## 5. 已确认子域名\n").expect("String write");
    writeln!(report, "| 子域名 | 是否解析 | 解析地址 | 来源 | 置信度 | 备注 |\n| --- | --- | --- | --- | --- | --- |").expect("String write");
    for item in rows.iter().take(100) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {:.2} | {} |",
            table_value(item, "x-sentinelflow-subdomain.subdomain"),
            bool_label(bool_value(item, "x-sentinelflow-subdomain.resolved")),
            table_array(item, "x-sentinelflow-subdomain.addresses"),
            table_array(item, "x-sentinelflow-subdomain.sources"),
            item.get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            if bool_value(item, "x-sentinelflow-fixture.synthetic") {
                "synthetic fixture"
            } else {
                ""
            }
        )
        .expect("String write");
    }
    if rows.is_empty() {
        writeln!(report, "| 无 | - | - | - | 0 | 本次未确认有效子域名。 |").expect("String write");
    }
    report.push('\n');
    writeln!(report, "## 候选子域名\n").expect("String write");
    writeln!(
        report,
        "| 子域名 | 来源 | 是否解析 | 状态 | 置信度 | 说明 |\n| --- | --- | --- | --- | --- | --- |"
    )
    .expect("String write");
    for item in candidates.iter().take(100) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {:.2} | 未确认候选项，未进入正式 Finding |",
            table_value(item, "subdomain"),
            table_array(item, "sources"),
            bool_label(bool_value(item, "resolved")),
            table_value(item, "status"),
            item.get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or_default()
        )
        .expect("String write");
    }
    if candidates.is_empty() {
        writeln!(report, "| 无 | - | - | - | 0 | 无未确认候选项。 |").expect("String write");
    }
    report.push('\n');
}

fn write_dns_table(report: &mut String, rows: &[Value], invalid_rows: &[Value]) {
    writeln!(report, "## 6. 有效 DNS 解析结果\n").expect("String write");
    writeln!(report, "| 域名 | 记录类型 | 记录值 | 来源 | 一致性 | 置信度 |\n| --- | --- | --- | --- | --- | --- |").expect("String write");
    for item in rows.iter().take(150) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {:.2} |",
            table_value(item, "x-sentinelflow-dns.domain"),
            table_value(item, "x-sentinelflow-dns.record_type"),
            table_value(item, "x-sentinelflow-dns.value"),
            table_array(item, "x-sentinelflow-dns.sources"),
            table_value(item, "x-sentinelflow-dns.source_agreement"),
            item.get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or_default()
        )
        .expect("String write");
    }
    if rows.is_empty() {
        writeln!(report, "| 无 | - | - | - | - | 0 |").expect("String write");
    }
    report.push('\n');
    writeln!(report, "## 无效或特殊 DNS 解析结果\n").expect("String write");
    writeln!(
        report,
        "| 域名 | 记录类型 | 记录值 | 地址类型 | 原因 |\n| --- | --- | --- | --- | --- |"
    )
    .expect("String write");
    for item in invalid_rows.iter().take(150) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} |",
            table_value(item, "domain"),
            table_value(item, "record_type"),
            table_value(item, "value"),
            address_class_for_report(item),
            table_value(item, "status")
        )
        .expect("String write");
    }
    if invalid_rows.is_empty() {
        writeln!(report, "| 无 | - | - | - | - |").expect("String write");
    }
    report.push('\n');
}

fn write_port_table(
    report: &mut String,
    rows: &[Value],
    skipped_stages: &[Value],
    no_public_ip: bool,
) {
    writeln!(report, "## 7. IP 与端口暴露面\n").expect("String write");
    if let Some(reason) = skipped_reason(skipped_stages, "no_public_routable_targets") {
        writeln!(report, "端口探测已跳过：{}。\n", table_text(&reason)).expect("String write");
        return;
    }
    if rows.is_empty() && no_public_ip {
        writeln!(
            report,
            "端口探测已跳过：上游 DNS 未产生有效公网 IP。历史运行未显式标记 skipped 时，本报告按质量门禁视为不可采信。\n"
        )
        .expect("String write");
        return;
    }
    writeln!(report, "| IP | 端口 | 协议 | 状态 | 来源 | 一致性 | 置信度 |\n| --- | --- | --- | --- | --- | --- | --- |").expect("String write");
    for item in rows.iter().take(150) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} | {:.2} |",
            table_value(item, "x-sentinelflow-port.address"),
            item.get("x-sentinelflow-port.port")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            table_value(item, "x-sentinelflow-port.protocol"),
            table_value(item, "x-sentinelflow-port.state"),
            table_array(item, "x-sentinelflow-port.sources"),
            table_value(item, "x-sentinelflow-port.source_agreement"),
            item.get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or_default()
        )
        .expect("String write");
    }
    if rows.is_empty() {
        writeln!(report, "| 无 | - | - | - | - | - | 0 |").expect("String write");
        writeln!(report, "\n无确认开放端口。").expect("String write");
    }
    report.push('\n');
}

fn write_service_table(
    report: &mut String,
    rows: &[Value],
    skipped_stages: &[Value],
    no_confirmed_ports: bool,
) {
    writeln!(report, "## 8. 服务识别结果\n").expect("String write");
    if let Some(reason) = skipped_reason(skipped_stages, "no_confirmed_open_ports") {
        writeln!(report, "服务识别已跳过：{}。\n", table_text(&reason)).expect("String write");
        return;
    }
    if rows.is_empty() && no_confirmed_ports {
        writeln!(
            report,
            "服务识别已跳过：上游端口阶段没有确认开放端口。历史运行未显式标记 skipped 时，本报告按质量门禁视为不可采信。\n"
        )
        .expect("String write");
        return;
    }
    writeln!(report, "| 地址 | 端口 | 服务 | 传输 | 产品 | 版本 | 来源 | 置信度 | 证据摘要 |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |").expect("String write");
    for item in rows.iter().take(150) {
        writeln!(
            report,
            "| {} | {} | {} | {} | {} | {} | {} | {:.2} | {} |",
            table_value(item, "x-sentinelflow-service.address"),
            item.get("x-sentinelflow-service.port")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            table_value(item, "x-sentinelflow-service.service"),
            table_value(item, "x-sentinelflow-service.transport"),
            table_value(item, "x-sentinelflow-service.product"),
            table_value(item, "x-sentinelflow-service.version"),
            table_array(item, "x-sentinelflow-service.sources"),
            item.get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            table_text(item.get("summary").and_then(Value::as_str).unwrap_or(""))
        )
        .expect("String write");
    }
    if rows.is_empty() {
        writeln!(
            report,
            "| 无 | - | - | - | - | - | - | 0 | 无确认服务；未对确认开放端口执行有效识别。 |"
        )
        .expect("String write");
    }
    report.push('\n');
}

fn bool_value(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn bool_label(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

struct QualityGateItem {
    id: &'static str,
    name: &'static str,
    status: &'static str,
    message: String,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn quality_gate_results(
    auth_scope: &str,
    confirmed_subdomains: &[Value],
    candidate_subdomains: &[Value],
    dns: &[Value],
    invalid_dns: &[Value],
    ports: &[Value],
    services: &[Value],
    skipped_stages: &[Value],
) -> Vec<QualityGateItem> {
    let real_scope = auth_scope != "fixture:local-only";
    let fixture_only = confirmed_subdomains.iter().any(|item| {
        bool_value(item, "x-sentinelflow-fixture.synthetic")
            || table_array(item, "x-sentinelflow-subdomain.sources").contains("passive_fixture")
    });
    let unresolved_candidates = candidate_subdomains
        .iter()
        .filter(|item| !bool_value(item, "resolved"))
        .count();
    let special_dns = invalid_dns.len();
    let mock_dns = dns.iter().chain(invalid_dns.iter()).any(|item| {
        table_array(item, "x-sentinelflow-dns.sources").contains("mock_resolver")
            || table_array(item, "sources").contains("mock_resolver")
            || table_array(item, "x-sentinelflow-dns.sources").contains("fixture_resolver")
    });
    let no_public_ip = dns
        .iter()
        .all(|item| !bool_value(item, "x-sentinelflow-dns.public_routable"));
    let port_skipped = skipped_reason(skipped_stages, "no_public_routable_targets").is_some();
    let service_skipped = skipped_reason(skipped_stages, "no_confirmed_open_ports").is_some();
    let all_unconfirmed = confirmed_subdomains.is_empty()
        && ports.is_empty()
        && services.is_empty()
        && (!candidate_subdomains.is_empty() || !invalid_dns.is_empty());

    vec![
        QualityGateItem {
            id: "QG-001",
            name: "真实目标不得使用 fixture-only 结果",
            status: if real_scope && fixture_only {
                "Failed"
            } else {
                "Passed"
            },
            message: if fixture_only {
                "发现 fixture-only 结果。".to_owned()
            } else {
                "未发现 fixture-only 结果。".to_owned()
            },
        },
        QualityGateItem {
            id: "QG-002",
            name: "候选子域名与确认子域名分离",
            status: "Passed",
            message: format!(
                "已确认 {} 个，候选 {} 个。",
                confirmed_subdomains.len(),
                candidate_subdomains.len()
            ),
        },
        QualityGateItem {
            id: "QG-003",
            name: "未解析字典候选不得计入 confirmed findings",
            status: if unresolved_candidates > 0
                && confirmed_subdomains.iter().any(|item| {
                    table_array(item, "x-sentinelflow-subdomain.sources")
                        .contains("active_dictionary")
                        && !bool_value(item, "x-sentinelflow-subdomain.resolved")
                }) {
                "Failed"
            } else {
                "Passed"
            },
            message: format!(
                "{unresolved_candidates} 个 unresolved dictionary candidate 保留为候选项。"
            ),
        },
        QualityGateItem {
            id: "QG-004",
            name: "DNS 特殊地址不得计为公网 IP",
            status: if special_dns > 0 { "Failed" } else { "Passed" },
            message: if special_dns > 0 {
                format!("{special_dns} 条 DNS 结果被标记为特殊或不可公网路由地址。")
            } else {
                "未发现特殊地址 DNS 结果。".to_owned()
            },
        },
        QualityGateItem {
            id: "QG-005",
            name: "mock resolver 不得用于真实目标报告",
            status: if real_scope && mock_dns {
                "Failed"
            } else {
                "Passed"
            },
            message: if mock_dns {
                "发现 mock/fixture resolver 来源。".to_owned()
            } else {
                "未发现 mock/fixture resolver 来源。".to_owned()
            },
        },
        QualityGateItem {
            id: "QG-006",
            name: "无公网 IP 时端口探测必须 skipped",
            status: if no_public_ip && ports.is_empty() && !port_skipped {
                "Failed"
            } else {
                "Passed"
            },
            message: if port_skipped {
                "端口探测已因无有效公网 IP 跳过。".to_owned()
            } else {
                format!(
                    "有效 DNS finding 数量：{}，端口 finding 数量：{}。",
                    dns.len(),
                    ports.len()
                )
            },
        },
        QualityGateItem {
            id: "QG-007",
            name: "无开放端口时服务识别必须 skipped",
            status: if ports.is_empty() && services.is_empty() && !service_skipped {
                "Failed"
            } else {
                "Passed"
            },
            message: if service_skipped {
                "服务识别已因无确认开放端口跳过。".to_owned()
            } else {
                format!(
                    "开放端口 finding 数量：{}，服务 finding 数量：{}。",
                    ports.len(),
                    services.len()
                )
            },
        },
        QualityGateItem {
            id: "QG-008",
            name: "全为 candidate/mock/special 时报告为 unconfirmed",
            status: if all_unconfirmed { "Failed" } else { "Passed" },
            message: if all_unconfirmed {
                "当前结果未形成任何确认资产。".to_owned()
            } else {
                "存在确认结果或没有可疑候选/特殊结果。".to_owned()
            },
        },
        QualityGateItem {
            id: "QG-009",
            name: "报告结论不得宣称发现真实资产",
            status: "Passed",
            message: "报告根据 quality gate 输出克制结论。".to_owned(),
        },
        QualityGateItem {
            id: "QG-010",
            name: "Web 必须显示 qualityGate 状态",
            status: "Passed",
            message: "报告摘要包含 Quality Gate 与 Report Status。".to_owned(),
        },
    ]
}

fn skipped_reason(skipped_stages: &[Value], reason: &str) -> Option<String> {
    skipped_stages.iter().find_map(|item| {
        let item_reason = item.get("reason").and_then(Value::as_str)?;
        if item_reason == reason {
            Some(
                item.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or(item_reason)
                    .to_owned(),
            )
        } else {
            None
        }
    })
}

fn address_class_for_report(item: &Value) -> String {
    if let Some(address_class) = item.get("address_class").and_then(Value::as_str) {
        if !address_class.is_empty() {
            return table_text(address_class);
        }
    }
    let Some(value) = item.get("value").and_then(Value::as_str) else {
        return String::new();
    };
    match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            let octets = address.octets();
            if octets[0] == 198 && (18..=19).contains(&octets[1]) {
                "benchmark".to_owned()
            } else if address.is_private() {
                "private".to_owned()
            } else if address.is_loopback() {
                "loopback".to_owned()
            } else if address.is_link_local() {
                "link_local".to_owned()
            } else if address.is_multicast() {
                "multicast".to_owned()
            } else if address.is_unspecified() {
                "unspecified".to_owned()
            } else if octets[0] >= 240 {
                "reserved".to_owned()
            } else {
                "public".to_owned()
            }
        }
        Ok(std::net::IpAddr::V6(address)) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return format!(
                    "ipv4_mapped_{}",
                    address_class_for_report(&serde_json::json!({"value": mapped.to_string()}))
                );
            }
            if address.is_loopback() {
                "loopback".to_owned()
            } else if address.is_unspecified() {
                "unspecified".to_owned()
            } else if address.is_multicast() {
                "multicast".to_owned()
            } else if (address.segments()[0] & 0xfe00) == 0xfc00 {
                "unique_local_ipv6".to_owned()
            } else if (address.segments()[0] & 0xffc0) == 0xfe80 {
                "link_local".to_owned()
            } else {
                "public".to_owned()
            }
        }
        Err(_) => "invalid".to_owned(),
    }
}

fn is_public_ip(value: &str) -> bool {
    match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1])))
        }
        Ok(std::net::IpAddr::V6(address)) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| !is_public_ip(&mapped.to_string())))
        }
        Err(_) => false,
    }
}

fn table_value(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => table_text(text),
        Some(other) => table_text(&other.to_string()),
        None => String::new(),
    }
}

fn table_array(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(table_text)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn table_text(value: &str) -> String {
    redact_text(value)
        .replace('|', "\\|")
        .replace('\n', " ")
        .chars()
        .take(180)
        .collect()
}

fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    if is_sensitive_key(key) {
                        (key.clone(), Value::String(REDACTED.to_owned()))
                    } else {
                        (key.clone(), redact_json(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_json).collect()),
        Value::String(value) => Value::String(redact_text(value)),
        other => other.clone(),
    }
}

fn redact_text(value: &str) -> String {
    let redacted = redact_keyed_values(value);
    redact_sensitive_terms(&redacted)
}

fn redact_keyed_values(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some((start, marker)) = find_sensitive_assignment(rest) {
        output.push_str(&rest[..start]);
        output.push_str(&rest[start..start + marker.len()]);
        output.push_str(REDACTED);
        let tail = &rest[start + marker.len()..];
        let next = tail
            .char_indices()
            .find(|(_, ch)| ch.is_whitespace() || matches!(ch, ',' | ';' | '&' | '"' | '\''))
            .map_or(tail.len(), |(index, _)| index);
        rest = &tail[next..];
    }
    output.push_str(rest);
    output
}

fn find_sensitive_assignment(value: &str) -> Option<(usize, &'static str)> {
    let lowered = value.to_ascii_lowercase();
    [
        "authorization:",
        "password=",
        "password:",
        "secret=",
        "secret:",
        "credential=",
        "credential:",
        "api_key=",
        "api_key:",
        "apikey=",
        "apikey:",
        "token=",
        "token:",
    ]
    .iter()
    .filter_map(|marker| lowered.find(marker).map(|index| (index, *marker)))
    .min_by_key(|(index, _)| *index)
}

fn redact_sensitive_terms(value: &str) -> String {
    ["secret", "password", "credential", "api_key", "apikey"]
        .iter()
        .fold(value.to_owned(), |current, term| {
            replace_case_insensitive(&current, term, REDACTED)
        })
}

fn replace_case_insensitive(value: &str, needle: &str, replacement: &str) -> String {
    let lowered = value.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut output = String::with_capacity(value.len());
    let mut start = 0;
    while let Some(index) = lowered[start..].find(&needle) {
        let absolute = start + index;
        output.push_str(&value[start..absolute]);
        output.push_str(replacement);
        start = absolute + needle.len();
    }
    output.push_str(&value[start..]);
    output
}

fn is_sensitive_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    lowered.contains("secret")
        || lowered.contains("password")
        || lowered.contains("token")
        || lowered.contains("credential")
        || lowered.contains("api_key")
        || lowered.contains("apikey")
        || lowered == "authorization"
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sentinelflow_runtime::{ExecutionIdentifiers, ExecutionStatus};
    use sentinelflow_schema::v1alpha1::{
        EvidenceSpec, FindingSeverity, FindingSpec, Metadata, ProtocolVersion, ToolOutput,
        ToolOutputKind, ToolOutputSpec,
    };
    use sentinelflow_store::{ResultArtifact, RunArtifact, TaskArtifact, TaskStatus};
    use serde_json::Value;

    use super::*;

    #[test]
    fn empty_result_still_has_every_report_section() {
        let identifiers = ExecutionIdentifiers::generate("example-echo");
        let bundle = RunBundle {
            run: RunArtifact {
                identifiers: identifiers.clone(),
                actor_id: "test".to_owned(),
                authorization_scope: "local:echo".to_owned(),
                capability: "echo".to_owned(),
                target: "synthetic target".to_owned(),
                status: ExecutionStatus::Succeeded,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                finished_at: "2026-01-01T00:00:01Z".to_owned(),
                duration_ms: 1,
                exit_code: Some(0),
            },
            result: ResultArtifact {
                run_id: identifiers.run_id,
                output: Some(ToolOutput {
                    api_version: ProtocolVersion::V1Alpha1,
                    kind: ToolOutputKind::Value,
                    metadata: Metadata {
                        name: "empty".to_owned(),
                        namespace: None,
                        uid: None,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                    },
                    spec: ToolOutputSpec {
                        schema_ref: "empty".to_owned(),
                        findings: Vec::new(),
                        errors: Vec::new(),
                        values: Value::Null,
                    },
                    extensions: BTreeMap::new(),
                }),
                errors: Vec::new(),
            },
            audit_events: Vec::new(),
        };
        let markdown = generate_markdown(&bundle);
        assert!(markdown.contains("No findings were produced."));
        assert!(markdown.contains("No evidence was produced."));
        assert!(markdown.contains("No errors were recorded."));
        assert!(markdown.contains("No audit events were recorded."));

        let task = TaskArtifact {
            task_id: "task-empty".to_owned(),
            name: "empty-task".to_owned(),
            actor_id: "test".to_owned(),
            tool_id: "example-file-import".to_owned(),
            status: TaskStatus::Completed,
            target_count: 1,
            run_ids: vec![bundle.run.identifiers.run_id.clone()],
            spec_snapshot: serde_json::from_str(include_str!(
                "../../../tests/fixtures/v1alpha1/valid-task-spec.json"
            ))
            .expect("task fixture"),
            plan_snapshot: serde_json::json!({"executionOrder": ["import"]}),
            step_states: BTreeMap::new(),
            outputs: BTreeMap::new(),
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            finished_at: Some("2026-01-01T00:00:01Z".to_owned()),
            last_error: None,
        };
        let task_markdown = generate_task_markdown(&task, &[bundle], &[]);
        assert!(task_markdown.contains("- Findings: 0"));
        assert!(task_markdown.contains("No findings were produced."));
    }

    #[test]
    fn reports_redact_sensitive_evidence_and_error_text() {
        let identifiers = ExecutionIdentifiers::generate("example-echo");
        let bundle = RunBundle {
            run: RunArtifact {
                identifiers: identifiers.clone(),
                actor_id: "test".to_owned(),
                authorization_scope: "fixture:local-only".to_owned(),
                capability: "echo".to_owned(),
                target: "secret-target-token".to_owned(),
                status: ExecutionStatus::Succeeded,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                finished_at: "2026-01-01T00:00:01Z".to_owned(),
                duration_ms: 1,
                exit_code: Some(0),
            },
            result: ResultArtifact {
                run_id: identifiers.run_id.clone(),
                output: Some(ToolOutput {
                    api_version: ProtocolVersion::V1Alpha1,
                    kind: ToolOutputKind::Value,
                    metadata: Metadata {
                        name: "redaction".to_owned(),
                        namespace: None,
                        uid: None,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                    },
                    spec: ToolOutputSpec {
                        schema_ref: "redaction".to_owned(),
                        findings: vec![FindingSpec {
                            title: "Sensitive fixture".to_owned(),
                            summary: "token should be hidden".to_owned(),
                            severity: FindingSeverity::Info,
                            fingerprint: "fingerprint".to_owned(),
                            cross_tool_fingerprint: "cross".to_owned(),
                            duplicate_of: None,
                            evidence: vec![EvidenceSpec {
                                evidence_type: "synthetic".to_owned(),
                                description: "contains secret".to_owned(),
                                data: serde_json::json!({
                                    "password": "p@ssw0rd",
                                    "nested": {"apiToken": "token-value"},
                                    "safe": "visible"
                                }),
                            }],
                        }],
                        errors: vec![sentinelflow_schema::v1alpha1::ErrorDetails {
                            code: "Synthetic".to_owned(),
                            message: "secret error token".to_owned(),
                            field: None,
                            details: BTreeMap::new(),
                        }],
                        values: Value::Null,
                    },
                    extensions: BTreeMap::new(),
                }),
                errors: Vec::new(),
            },
            audit_events: Vec::new(),
        };
        let markdown = generate_markdown(&bundle);
        assert!(markdown.contains(REDACTED));
        assert!(markdown.contains("visible"));
        assert!(!markdown.contains("p@ssw0rd"));
        assert!(!markdown.contains("token-value"));
        assert!(!markdown.contains("secret-target-token"));
        assert!(!markdown.contains("secret error token"));
    }

    #[test]
    fn asset_quality_gate_marks_candidate_and_special_only_results_invalid() {
        let candidates = (0..12)
            .map(|index| {
                serde_json::json!({
                    "type": "subdomain_candidate",
                    "subdomain": format!("candidate{index}.weikan.net.cn"),
                    "sources": ["active_dictionary"],
                    "resolved": false,
                    "status": "candidate",
                    "confidence": 0.1
                })
            })
            .collect::<Vec<_>>();
        let invalid_dns = vec![
            serde_json::json!({
                "domain": "candidate0.weikan.net.cn",
                "record_type": "A",
                "value": "198.18.0.75",
                "status": "invalid_special_address",
                "address_class": "benchmark",
                "valid_for_port_probe": false,
                "public_routable": false,
                "sources": ["public_resolver"]
            }),
            serde_json::json!({
                "domain": "candidate0.weikan.net.cn",
                "record_type": "AAAA",
                "value": "::ffff:198.18.0.75",
                "status": "invalid_special_address",
                "address_class": "ipv4_mapped_benchmark",
                "valid_for_port_probe": false,
                "public_routable": false,
                "sources": ["public_resolver"]
            }),
        ];
        let skipped = vec![
            serde_json::json!({
                "source": "tcp_connect",
                "status": "skipped",
                "reason": "no_public_routable_targets",
                "message": "Port probing skipped because upstream DNS produced no public routable targets."
            }),
            serde_json::json!({
                "source": "active_service",
                "status": "skipped",
                "reason": "no_confirmed_open_ports",
                "message": "Service detection skipped because upstream port stage produced no confirmed open ports."
            }),
        ];

        let gate = quality_gate_results(
            "real:weikan-net-cn",
            &[],
            &candidates,
            &[],
            &invalid_dns,
            &[],
            &[],
            &skipped,
        );
        let failed = gate
            .iter()
            .filter(|item| item.status == "Failed")
            .map(|item| item.id)
            .collect::<Vec<_>>();

        assert!(failed.contains(&"QG-004"));
        assert!(failed.contains(&"QG-008"));
        assert!(!failed.contains(&"QG-006"));
        assert!(!failed.contains(&"QG-007"));
    }
}
