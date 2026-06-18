#!/usr/bin/env python3
"""Bounded Markdown report generation for normalized SentinelFlow data."""

from __future__ import annotations

import json
import re
import sys
from typing import Any


SOURCE = "markdown-report-plus"
MAX_REPORT_BYTES = 1_048_576
SECRET_KEY_PATTERN = re.compile(r"(secret|token|api[_-]?key|authorization|password|credential)", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)


class InputError(Exception):
    """Controlled input validation error."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.field = field


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"invalid JSON input: {error}", file=sys.stderr)
        return 2
    try:
        output = run(payload)
    except InputError as error:
        print(f"{error.field}: {error}", file=sys.stderr)
        return 2
    json.dump(output, sys.stdout, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise InputError("input must be a JSON object", "$")
    target = object_at(payload, "target", "$.target")
    options = object_at(payload, "options", "$.options")
    data = object_at(payload, "data", "$.data")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"summary", "asset_discovery", "audit"}:
        raise InputError("unsupported report mode", "$.options.mode")
    title = sanitize_line(string_at(options, "title", "$.options.title"), 160)
    include = object_at(options, "include", "$.options.include")
    limits = options.get("limits", {}) if isinstance(options.get("limits", {}), dict) else {}
    max_findings = bounded_int(limits.get("max_findings"), 100, 0, 1000)
    max_evidence = bounded_int(limits.get("max_evidence_per_finding"), 5, 0, 20)
    max_audit = bounded_int(limits.get("max_audit_events"), 100, 0, 1000)
    max_bytes = bounded_int(limits.get("max_markdown_bytes"), 131072, 1024, MAX_REPORT_BYTES)

    findings = array_at(data, "findings", "$.data.findings")[:max_findings]
    errors = array_at(data, "errors", "$.data.errors")
    audit_events = array_at(data, "audit_events", "$.data.audit_events")[:max_audit]
    runs = array_at(data, "runs", "$.data.runs")
    source_status = array_at(data, "source_status", "$.data.source_status")
    redactor = Redactor()
    markdown, sections = render_markdown(
        title=title,
        mode=mode,
        target=target,
        runs=runs,
        findings=findings,
        errors=errors,
        audit_events=audit_events,
        source_status=source_status,
        include=include,
        max_evidence=max_evidence,
        redactor=redactor,
    )
    markdown, truncated = enforce_byte_limit(markdown, max_bytes)
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "report": {
            "type": "markdown_report",
            "title": title,
            "markdown": markdown,
            "sections": sections,
            "bytes": len(markdown.encode("utf-8")),
            "truncated": truncated,
            "redaction_count": redactor.count,
        },
        "summary": {
            "run_count": len(runs),
            "finding_count": len(array_at(data, "findings", "$.data.findings")),
            "rendered_finding_count": len(findings),
            "error_count": len(errors),
            "audit_event_count": len(array_at(data, "audit_events", "$.data.audit_events")),
            "rendered_audit_event_count": len(audit_events),
            "source_status_count": len(source_status),
            "sections": sections,
        },
        "source_status": [{"source": SOURCE, "status": "ok", "message": "Markdown report generated.", "query_count": 0, "probe_count": 0}],
        "errors": [],
        "safety": {
            "network_connections": 0,
            "shell_commands": 0,
            "dynamic_libraries_loaded": False,
            "template_user_supplied": False,
            "secret_redaction_enabled": True,
            "redaction_count": redactor.count,
            "max_markdown_bytes": max_bytes,
        },
    }


def render_markdown(
    *,
    title: str,
    mode: str,
    target: dict[str, Any],
    runs: list[Any],
    findings: list[Any],
    errors: list[Any],
    audit_events: list[Any],
    source_status: list[Any],
    include: dict[str, Any],
    max_evidence: int,
    redactor: "Redactor",
) -> tuple[str, list[str]]:
    lines: list[str] = [f"# {escape_markdown(title)}", ""]
    sections: list[str] = []
    if bool(include.get("summary")):
        sections.append("summary")
        lines.extend([
            "## Summary",
            "",
            f"- Target: `{escape_inline(target.get('value'))}`",
            f"- Mode: `{mode}`",
            f"- Runs: {len(runs)}",
            f"- Findings rendered: {len(findings)}",
            f"- Errors: {len(errors)}",
            f"- Audit events rendered: {len(audit_events)}",
            "",
        ])
    if mode == "asset_discovery":
        sections.append("asset-discovery")
        counts = classify_findings(findings)
        lines.extend(["## Asset Discovery Overview", ""])
        for key in ["subdomain", "dns", "exposure", "port", "http", "web", "tls", "service", "other"]:
            lines.append(f"- {key}: {counts.get(key, 0)}")
        lines.append("")
    if bool(include.get("findings")):
        sections.append("findings")
        lines.extend(["## Findings", ""])
        if not findings:
            lines.extend(["No findings were provided.", ""])
        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue
            title_text = redactor.clean(sanitize_line(finding.get("title", "Untitled finding"), 160))
            severity = redactor.clean(sanitize_line(finding.get("severity", "unknown"), 40))
            summary = redactor.clean(sanitize_line(finding.get("summary", ""), 600))
            lines.extend([f"### {index}. {escape_markdown(title_text)}", "", f"- Severity: `{escape_inline(severity)}`"])
            if summary:
                lines.extend([f"- Summary: {escape_markdown(summary)}"])
            if bool(include.get("evidence")):
                evidence_items = finding.get("evidence", [])
                if isinstance(evidence_items, list) and max_evidence > 0:
                    lines.append("- Evidence:")
                    for evidence in evidence_items[:max_evidence]:
                        lines.append(f"  - {render_evidence(evidence, redactor)}")
            lines.append("")
    if source_status:
        sections.append("source-status")
        lines.extend(["## Source Status", ""])
        for item in source_status[:100]:
            if not isinstance(item, dict):
                continue
            source = redactor.clean(sanitize_line(item.get("source", "unknown"), 80))
            status = redactor.clean(sanitize_line(item.get("status", "unknown"), 80))
            message = redactor.clean(sanitize_line(item.get("message", ""), 200))
            lines.append(f"- `{escape_inline(source)}`: `{escape_inline(status)}` {escape_markdown(message)}")
        lines.append("")
    if bool(include.get("errors")):
        sections.append("errors")
        lines.extend(["## Errors", ""])
        if not errors:
            lines.extend(["No errors were provided.", ""])
        for error in errors[:100]:
            if not isinstance(error, dict):
                continue
            code = redactor.clean(sanitize_line(error.get("code", "Error"), 80))
            message = redactor.clean(sanitize_line(error.get("message", ""), 400))
            lines.append(f"- `{escape_inline(code)}`: {escape_markdown(message)}")
        lines.append("")
    if bool(include.get("audit")):
        sections.append("audit")
        lines.extend(["## Audit", ""])
        if not audit_events:
            lines.extend(["No audit events were provided.", ""])
        for event in audit_events:
            if not isinstance(event, dict):
                continue
            action = redactor.clean(sanitize_line(event.get("action", "unknown"), 100))
            outcome = redactor.clean(sanitize_line(event.get("outcome", "unknown"), 80))
            timestamp = redactor.clean(sanitize_line(event.get("timestamp", ""), 80))
            lines.append(f"- `{escape_inline(action)}`: `{escape_inline(outcome)}` {escape_markdown(timestamp)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n", sections


def classify_findings(findings: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        category = "other"
        for evidence in finding.get("evidence", []) if isinstance(finding.get("evidence", []), list) else []:
            if not isinstance(evidence, dict):
                continue
            data = evidence.get("data", {})
            finding_type = str(data.get("findingType", "") if isinstance(data, dict) else "")
            evidence_type = str(evidence.get("evidenceType", ""))
            marker = f"{finding_type} {evidence_type}"
            if "subdomain" in marker:
                category = "subdomain"
            elif "dns" in marker:
                category = "dns"
            elif "exposure" in marker:
                category = "exposure"
            elif "port" in marker:
                category = "port"
            elif "http" in marker:
                category = "http"
            elif "web" in marker or "fingerprint" in marker:
                category = "web"
            elif "tls" in marker or "certificate" in marker:
                category = "tls"
            elif "service" in marker:
                category = "service"
        counts[category] = counts.get(category, 0) + 1
    return counts


def render_evidence(evidence: Any, redactor: "Redactor") -> str:
    if not isinstance(evidence, dict):
        return "invalid evidence"
    evidence_type = redactor.clean(sanitize_line(evidence.get("evidenceType", "evidence"), 80))
    description = redactor.clean(sanitize_line(evidence.get("description", ""), 200))
    data = evidence.get("data", {}) if isinstance(evidence.get("data", {}), dict) else {}
    target = data.get("target", {}) if isinstance(data.get("target", {}), dict) else {}
    target_value = redactor.clean(sanitize_line(target.get("value", ""), 200))
    confidence = data.get("confidence")
    confidence_text = f", confidence={confidence:.2f}" if isinstance(confidence, (int, float)) else ""
    target_text = f", target=`{escape_inline(target_value)}`" if target_value else ""
    details = json.dumps(redactor.clean_json(data), ensure_ascii=True, sort_keys=True)
    details = sanitize_line(details, 500)
    return f"`{escape_inline(evidence_type)}` {escape_markdown(description)}{target_text}{confidence_text}, data=`{escape_inline(details)}`"


class Redactor:
    def __init__(self) -> None:
        self.count = 0

    def clean(self, value: Any) -> str:
        text = str(value)
        replaced = SECRET_VALUE_PATTERN.sub(lambda match: self._replace(match.group(1)), text)
        return replaced

    def clean_json(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                if SECRET_KEY_PATTERN.search(str(key)):
                    self.count += 1
                    cleaned[key] = "[REDACTED]"
                else:
                    cleaned[key] = self.clean_json(item)
            return cleaned
        if isinstance(value, list):
            return [self.clean_json(item) for item in value]
        if isinstance(value, str):
            return self.clean(value)
        return value

    def _replace(self, prefix: str) -> str:
        self.count += 1
        return f"{prefix}[REDACTED]"


def enforce_byte_limit(markdown: str, max_bytes: int) -> tuple[str, bool]:
    encoded = markdown.encode("utf-8")
    if len(encoded) <= max_bytes:
        return markdown, False
    suffix = "\n\n_Report truncated by markdown-report-plus output limit._\n"
    budget = max(0, max_bytes - len(suffix.encode("utf-8")))
    clipped = encoded[:budget].decode("utf-8", errors="ignore")
    return clipped.rstrip() + suffix, True


def object_at(value: dict[str, Any], field: str, path: str) -> dict[str, Any]:
    item = value.get(field)
    if not isinstance(item, dict):
        raise InputError("field must be an object", path)
    return item


def array_at(value: dict[str, Any], field: str, path: str) -> list[Any]:
    item = value.get(field, [])
    if item is None:
        return []
    if not isinstance(item, list):
        raise InputError("field must be an array", path)
    return item


def string_at(value: dict[str, Any], field: str, path: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise InputError("field must be a non-empty string", path)
    return item.strip()


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if not isinstance(value, int):
        return default
    return min(max(value, minimum), maximum)


def sanitize_line(value: Any, limit: int) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def escape_markdown(value: str) -> str:
    return value.replace("|", "\\|")


def escape_inline(value: Any) -> str:
    return str(value).replace("`", "'")[:240]


if __name__ == "__main__":
    raise SystemExit(main())
