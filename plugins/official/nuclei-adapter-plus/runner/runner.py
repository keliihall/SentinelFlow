#!/usr/bin/env python3
"""Bounded Nuclei JSONL result adapter for SentinelFlow."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "nuclei-adapter-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SECRET_PATTERN = re.compile(r"(?i)(password|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+")
AUTH_HEADER_PATTERN = re.compile(r"(?i)(authorization:\s*)(bearer|basic)\s+[^'\"\s]+")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


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
    except OSError as error:
        print(f"runner import failure: {safe_message(error)}", file=sys.stderr)
        return 2
    json.dump(output, sys.stdout, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def run(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise InputError("input must be a JSON object", "$")
    context = object_at(payload, "context", "$.context")
    authorization_scope = string_at(context, "authorization_scope", "$.context.authorization_scope")
    target = object_at(payload, "target", "$.target")
    if string_at(target, "type", "$.target.type") not in {"url", "domain", "report"}:
        raise InputError("target.type must be url, domain, or report", "$.target.type")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "local_file"}:
        raise InputError("unsupported Nuclei adapter mode", "$.options.mode")
    import_options = object_at(options, "import", "$.options.import")
    template_options = object_at(options, "templates", "$.options.templates")
    output_options = object_at(options, "output", "$.options.output")
    fmt = string_at(import_options, "format", "$.options.import.format")
    if fmt != "nuclei_jsonl":
        raise InputError("unsupported import format", "$.options.import.format")
    policy = object_at(payload, "policy", "$.policy")
    if bool(policy.get("allow_active_verify")):
        raise InputError("active Nuclei execution is not supported by this adapter", "$.policy.allow_active_verify")
    if bool(policy.get("allow_high_risk")):
        raise InputError("high-risk Nuclei templates are not supported by this adapter", "$.policy.allow_high_risk")
    if bool(policy.get("allow_intrusive_templates")):
        raise InputError("intrusive templates are not supported by this adapter", "$.policy.allow_intrusive_templates")

    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if mode == "dry_run":
        return build_output(target, mode, fmt, authorization_scope, [], source_status, errors, 0, 0, 0)

    path = resolve_plugin_file(string_at(import_options, "file", "$.options.import.file"))
    max_records = bounded_int(import_options.get("max_records"), 1000, 0, MAX_RESULTS)
    rules = template_rules(template_options)
    raw_records = parse_jsonl(path)
    imported_count = len(raw_records)
    skipped_count = 0
    results = []
    for raw in raw_records:
        normalized = normalize_record(raw, fmt)
        decision = evaluate_template(normalized, rules)
        if decision is not None:
            skipped_count += 1
            if len(errors) < MAX_ERRORS:
                errors.append(decision)
            continue
        results.append(normalized)
        if len(results) >= max_records:
            break
    if not bool(output_options.get("include_request")):
        for result in results:
            result["request"] = None
            result["curl_command"] = None
    if not bool(output_options.get("include_extracted_results")):
        for result in results:
            result["extracted_results"] = []
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    source_status.append(
        {
            "source": fmt,
            "status": "ok",
            "message": f"{fmt} report imported with Nuclei template policy controls.",
            "query_count": 0,
            "probe_count": 0,
            "record_count": imported_count,
            "skipped_count": skipped_count,
        }
    )
    return build_output(target, mode, fmt, authorization_scope, results, source_status, errors, imported_count, len(results), skipped_count)


def parse_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as error:
                raise InputError(f"invalid JSONL record at line {line_number}: {error}", "$.options.import.file") from error
            if isinstance(value, dict):
                records.append(value)
    return records


def normalize_record(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    severity = normalize_severity(info.get("severity"))
    matched_at = truncate(record.get("matched-at") or record.get("matched_at") or record.get("host") or "unknown", 2048) or "unknown"
    template_id = truncate(record.get("template-id") or record.get("template_id") or "unknown", 256) or "unknown"
    template_path = truncate(record.get("template-path") or record.get("template_path"), 512)
    template_name = truncate(info.get("name") or template_id, 256) or template_id
    tags = normalize_tags(info.get("tags"))
    description = redact(truncate(info.get("description"), 2048))
    request = redact_auth(truncate(record.get("request"), 4096))
    curl_command = redact_auth(redact(truncate(record.get("curl-command") or record.get("curl_command"), 4096)))
    extracted_results = [redact(item) or "" for item in normalize_list(record.get("extracted-results") or record.get("extracted_results"), 512)]
    port = parse_port(record.get("port"))
    cves = normalize_cves(classification.get("cve-id") or classification.get("cve_id"), record)
    cwes = normalize_cwes(classification.get("cwe-id") or classification.get("cwe_id"), record)
    references = normalize_list(info.get("reference") or info.get("references"), 1024)
    result = {
        "type": "nuclei_result",
        "matched_at": matched_at,
        "host": truncate(record.get("host"), 2048),
        "ip": truncate(record.get("ip"), 64),
        "scheme": truncate(record.get("scheme"), 16),
        "port": port,
        "template_id": template_id,
        "template_path": template_path,
        "template_name": template_name,
        "template_severity": severity,
        "tags": tags,
        "description": description,
        "matcher_name": truncate(record.get("matcher-name") or record.get("matcher_name"), 128),
        "extractor_name": truncate(record.get("extractor-name") or record.get("extractor_name"), 128),
        "type_name": truncate(record.get("type"), 64),
        "cve": cves,
        "cwe": cwes,
        "cvss_score": parse_float(classification.get("cvss-score") or classification.get("cvss_score")),
        "references": references,
        "extracted_results": extracted_results,
        "request": request,
        "curl_command": curl_command,
        "observed_at": truncate(record.get("timestamp"), 64),
        "sources": [fmt],
        "source_count": 1,
        "source_details": [{"source": fmt, "template_id": template_id, "template_path": template_path, "matched_at": matched_at}],
        "confidence": confidence_for_severity(severity),
        "evidence": {
            "summary": f"Nuclei imported {severity} template result {template_id} on {matched_at}.",
            "items": [{"matcher": record.get("matcher-name"), "extracted_results": extracted_results}],
        },
    }
    return result


def template_rules(options: dict[str, Any]) -> dict[str, Any]:
    allowed_prefixes = [str(item).strip() for item in options.get("allowed_path_prefixes", []) if str(item).strip()]
    allowed_severities = {normalize_severity(item) for item in options.get("allowed_severities", [])}
    blocked_tags = {str(item).strip().lower() for item in options.get("blocked_tags", []) if str(item).strip()}
    allow_medium = bool(options.get("allow_medium_or_higher"))
    if not allowed_prefixes:
        raise InputError("at least one template path prefix is required", "$.options.templates.allowed_path_prefixes")
    if not allowed_severities:
        raise InputError("at least one allowed severity is required", "$.options.templates.allowed_severities")
    if any(SEVERITY_ORDER[item] >= SEVERITY_ORDER["medium"] for item in allowed_severities) and not allow_medium:
        raise InputError("medium-or-higher template severities require explicit approval", "$.options.templates.allow_medium_or_higher")
    return {"allowed_prefixes": allowed_prefixes, "allowed_severities": allowed_severities, "blocked_tags": blocked_tags}


def evaluate_template(result: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any] | None:
    template_path = result.get("template_path") or ""
    template_id = result.get("template_id") or "unknown"
    if template_path and not any(str(template_path).startswith(prefix) for prefix in rules["allowed_prefixes"]):
        return skip_error(template_id, "template path is outside the allowlist", "$.options.templates.allowed_path_prefixes")
    severity = result.get("template_severity")
    if severity not in rules["allowed_severities"]:
        return skip_error(template_id, f"template severity {severity} is not allowed", "$.options.templates.allowed_severities")
    blocked = sorted(set(result.get("tags", [])) & rules["blocked_tags"])
    if blocked:
        return skip_error(template_id, f"template tags are blocked: {', '.join(blocked)}", "$.options.templates.blocked_tags")
    return None


def skip_error(template_id: str, message: str, field: str) -> dict[str, Any]:
    return {"code": "TemplatePolicySkipped", "message": message, "field": field, "template_id": template_id}


def build_output(target: dict[str, Any], mode: str, fmt: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], imported_count: int, result_count: int, skipped_count: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "format": fmt,
        "results": results[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "imported_record_count": imported_count,
            "result_count": result_count,
            "skipped_record_count": skipped_count,
            "requires_active_verify": False,
            "requires_high_risk": False,
            "requires_approval": False,
            "source_status_count": len(source_status),
            "error_count": len(errors),
            "authorization_scope": authorization_scope,
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "authorization_scope_required": True,
            "offline_import_only": True,
            "active_target_connections": 0,
            "scanner_invocations": 0,
            "template_execution": False,
            "exploit_attempts": 0,
            "credential_use": False,
            "secret_redaction_enabled": True,
            "template_path_allowlist_enforced": True,
            "blocked_tags_enforced": True,
        },
    }


def normalize_severity(value: Any) -> str:
    text = str(value or "info").strip().lower()
    return text if text in SEVERITY_ORDER else "info"


def confidence_for_severity(severity: str) -> float:
    return {"info": 0.60, "low": 0.72, "medium": 0.80, "high": 0.88, "critical": 0.92}.get(severity, 0.70)


def normalize_tags(value: Any) -> list[str]:
    return [item.lower() for item in normalize_list(value, 64)]


def normalize_cves(value: Any, record: dict[str, Any]) -> list[str]:
    candidates = normalize_list(value, 128)
    text = json.dumps(record, ensure_ascii=True)
    candidates.extend(match.upper() for match in CVE_PATTERN.findall(text))
    result = []
    for item in candidates:
        normalized = str(item).strip().upper()
        if CVE_PATTERN.fullmatch(normalized) and normalized not in result:
            result.append(normalized)
    return result[:64]


def normalize_cwes(value: Any, record: dict[str, Any]) -> list[str]:
    candidates = normalize_list(value, 128)
    text = json.dumps(record, ensure_ascii=True)
    candidates.extend(match.upper() for match in CWE_PATTERN.findall(text))
    result = []
    for item in candidates:
        normalized = str(item).strip().upper()
        if CWE_PATTERN.fullmatch(normalized) and normalized not in result:
            result.append(normalized)
    return result[:64]


def normalize_list(value: Any, limit: int = 256) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[,;\s]+", str(value))
    result = []
    for item in items:
        text = str(item).strip()
        if text and text not in result:
            result.append(text[:limit])
    return result


def parse_port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def parse_float(value: Any) -> float | None:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return min(max(number, 0.0), 10.0)


def resolve_plugin_file(value: str) -> Path:
    path = Path(value)
    candidate = path if path.is_absolute() else PLUGIN_ROOT / path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise InputError("import file must exist under plugin root", "$.options.import.file") from error
    try:
        resolved.relative_to(PLUGIN_ROOT)
    except ValueError as error:
        raise InputError("import file must stay under plugin root", "$.options.import.file") from error
    if not resolved.is_file():
        raise InputError("file path must point to a regular file", "$.options.import.file")
    if resolved.stat().st_size > 4_194_304:
        raise InputError("import file exceeds plugin limit", "$.options.import.file")
    return resolved


def object_at(payload: dict[str, Any], field: str, path: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise InputError(f"{field} must be an object", path)
    return value


def string_at(payload: dict[str, Any], field: str, path: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{field} must be a non-empty string", path)
    return value


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def truncate(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_PATTERN.sub(lambda match: match.group(1) + "=[REDACTED]", value)


def redact_auth(value: str | None) -> str | None:
    if value is None:
        return None
    return AUTH_HEADER_PATTERN.sub(lambda match: match.group(1) + match.group(2) + " [REDACTED]", value)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
