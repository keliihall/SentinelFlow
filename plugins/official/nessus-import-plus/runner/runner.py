#!/usr/bin/env python3
"""Offline Nessus report import for SentinelFlow."""

from __future__ import annotations

import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "nessus-import-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SEVERITY_TO_INT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INT_TO_SEVERITY = {value: key for key, value in SEVERITY_TO_INT.items()}
SECRET_PATTERN = re.compile(r"(?i)(password|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


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
    except (OSError, ET.ParseError) as error:
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
    if string_at(target, "type", "$.target.type") != "report":
        raise InputError("target.type must be report", "$.target.type")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "local_file"}:
        raise InputError("unsupported Nessus import mode", "$.options.mode")
    import_options = object_at(options, "import", "$.options.import")
    output_options = object_at(options, "output", "$.options.output")
    fmt = string_at(import_options, "format", "$.options.import.format")
    if fmt not in {"nessus_xml", "json", "csv"}:
        raise InputError("unsupported import format", "$.options.import.format")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if mode == "dry_run":
        return build_output(target, mode, fmt, authorization_scope, [], source_status, errors, 0, 0)

    path = resolve_plugin_file(string_at(import_options, "file", "$.options.import.file"))
    max_records = bounded_int(import_options.get("max_records"), 1000, 0, MAX_RESULTS)
    minimum = severity_int(string_at(import_options, "minimum_severity", "$.options.import.minimum_severity"))
    include_info = bool(import_options.get("include_info"))
    raw_records = parse_file(fmt, path)
    imported_count = len(raw_records)
    results = []
    for raw in raw_records:
        result = normalize_record(raw, fmt)
        if result["severity"] == 0 and not include_info:
            continue
        if result["severity"] < minimum:
            continue
        results.append(result)
        if len(results) >= max_records:
            break
    if not bool(output_options.get("include_description")):
        for result in results:
            result["description"] = None
    if not bool(output_options.get("include_solution")):
        for result in results:
            result["solution"] = None
    if not bool(output_options.get("include_evidence")):
        for result in results:
            result["plugin_output"] = None
            result["evidence"]["items"] = []
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    source_status.append({"source": fmt, "status": "ok", "message": f"{fmt} report imported.", "query_count": 0, "probe_count": 0, "record_count": imported_count})
    return build_output(target, mode, fmt, authorization_scope, results, source_status, errors, imported_count, len(results))


def parse_file(fmt: str, path: Path) -> list[dict[str, Any]]:
    if fmt == "nessus_xml":
        return parse_nessus_xml(path)
    if fmt == "json":
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        records = data.get("findings", data if isinstance(data, list) else [])
        if not isinstance(records, list):
            raise InputError("JSON import must contain an array or findings array", "$.options.import.file")
        return [record for record in records if isinstance(record, dict)]
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def parse_nessus_xml(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    records = []
    for host in tree.findall(".//ReportHost"):
        host_name = host.attrib.get("name", "")
        host_ip = None
        for tag in host.findall("./HostProperties/tag"):
            if tag.attrib.get("name") == "host-ip":
                host_ip = safe_text(tag.text)
        for item in host.findall("./ReportItem"):
            record: dict[str, Any] = {
                "host": host_name or host_ip or "unknown",
                "host_ip": host_ip,
                "port": item.attrib.get("port"),
                "protocol": item.attrib.get("protocol"),
                "service": item.attrib.get("svc_name"),
                "plugin_id": item.attrib.get("pluginID"),
                "plugin_name": item.attrib.get("pluginName"),
                "plugin_family": item.attrib.get("pluginFamily"),
                "severity": item.attrib.get("severity"),
            }
            for child in item:
                key = child.tag
                value = safe_text(child.text)
                if key == "cve":
                    record.setdefault("cve", []).append(value)
                else:
                    record[key] = value
            records.append(record)
    return records


def normalize_record(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    severity = severity_int(record.get("severity"))
    severity_label = INT_TO_SEVERITY[severity]
    cves = normalize_cves(record.get("cve"), record)
    host = truncate(record.get("host") or record.get("hostname") or record.get("host_ip") or "unknown", 253) or "unknown"
    port = parse_port(record.get("port"))
    protocol = truncate(record.get("protocol"), 32)
    service = truncate(record.get("service") or record.get("svc_name"), 64)
    plugin_id = truncate(record.get("plugin_id") or record.get("pluginID") or record.get("plugin_id".replace("_", "")) or "unknown", 128) or "unknown"
    plugin_name = truncate(record.get("plugin_name") or record.get("pluginName") or "Unnamed Nessus plugin", 256) or "Unnamed Nessus plugin"
    synopsis = redact(truncate(record.get("synopsis"), 512))
    description = redact(truncate(record.get("description"), 2048))
    solution = redact(truncate(record.get("solution"), 1024))
    plugin_output = redact(truncate(record.get("plugin_output") or record.get("evidence"), 2048))
    result = {
        "type": "vulnerability_import_result",
        "host": host,
        "host_ip": truncate(record.get("host_ip"), 64),
        "port": port,
        "protocol": protocol,
        "service": service,
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "plugin_family": truncate(record.get("plugin_family") or record.get("pluginFamily"), 128),
        "severity": severity,
        "severity_label": severity_label,
        "cve": cves,
        "cwe": normalize_list(record.get("cwe")),
        "cvss_base_score": parse_float(record.get("cvss_base_score") or record.get("cvss")),
        "synopsis": synopsis,
        "description": description,
        "solution": solution,
        "plugin_output": plugin_output,
        "sources": [fmt],
        "source_count": 1,
        "source_details": [{"source": fmt, "plugin_id": plugin_id, "host": host, "port": port}],
        "confidence": confidence_for_severity(severity),
        "evidence": {"summary": synopsis or f"Nessus imported {severity_label} finding {plugin_name} on {host}.", "items": [{"plugin_output": plugin_output}] if plugin_output else []},
    }
    return result


def build_output(target: dict[str, Any], mode: str, fmt: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], imported_count: int, result_count: int) -> dict[str, Any]:
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
            "exploit_attempts": 0,
            "credential_use": False,
            "secret_redaction_enabled": True,
        },
    }


def severity_int(value: Any) -> int:
    if isinstance(value, int):
        return min(max(value, 0), 4)
    text = str(value).strip().lower()
    if text.isdigit():
        return min(max(int(text), 0), 4)
    return SEVERITY_TO_INT.get(text, 0)


def confidence_for_severity(severity: int) -> float:
    return {0: 0.60, 1: 0.72, 2: 0.80, 3: 0.86, 4: 0.90}.get(severity, 0.70)


def normalize_cves(value: Any, record: dict[str, Any]) -> list[str]:
    candidates = normalize_list(value)
    for field in ("synopsis", "description", "plugin_output", "evidence"):
        text = record.get(field)
        if isinstance(text, str):
            candidates.extend(match.upper() for match in CVE_PATTERN.findall(text))
    result = []
    for item in candidates:
        normalized = str(item).strip().upper()
        if CVE_PATTERN.fullmatch(normalized) and normalized not in result:
            result.append(normalized)
    return result[:64]


def normalize_list(value: Any) -> list[str]:
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
            result.append(text[:128])
    return result


def parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def parse_float(value: Any) -> float | None:
    try:
        number = float(value)
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


def safe_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def truncate(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_PATTERN.sub(lambda match: match.group(1) + "=[REDACTED]", value)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
