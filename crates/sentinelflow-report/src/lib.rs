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
}
