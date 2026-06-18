#!/usr/bin/env python3
"""Offline OpenVAS or Greenbone report import for SentinelFlow."""

from __future__ import annotations

import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "openvas-import-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SEVERITY_TO_INT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INT_TO_SEVERITY = {value: key for key, value in SEVERITY_TO_INT.items()}
THREAT_TO_SEVERITY = {
    "debug": 0,
    "log": 0,
    "false positive": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
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
        raise InputError("unsupported OpenVAS import mode", "$.options.mode")
    import_options = object_at(options, "import", "$.options.import")
    output_options = object_at(options, "output", "$.options.output")
    fmt = string_at(import_options, "format", "$.options.import.format")
    if fmt not in {"openvas_xml", "csv"}:
        raise InputError("unsupported import format", "$.options.import.format")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if mode == "dry_run":
        return build_output(target, mode, fmt, authorization_scope, [], source_status, errors, 0, 0)

    path = resolve_plugin_file(string_at(import_options, "file", "$.options.import.file"))
    max_records = bounded_int(import_options.get("max_records"), 1000, 0, MAX_RESULTS)
    minimum = severity_int(string_at(import_options, "minimum_severity", "$.options.import.minimum_severity"))
    include_log = bool(import_options.get("include_log"))
    raw_records = parse_file(fmt, path)
    imported_count = len(raw_records)
    results = []
    for raw in raw_records:
        result = normalize_record(raw, fmt)
        if result["severity"] == 0 and not include_log:
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
            result["evidence_text"] = None
            result["evidence"]["items"] = []
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    source_status.append(
        {
            "source": fmt,
            "status": "ok",
            "message": f"{fmt} report imported.",
            "query_count": 0,
            "probe_count": 0,
            "record_count": imported_count,
        }
    )
    return build_output(target, mode, fmt, authorization_scope, results, source_status, errors, imported_count, len(results))


def parse_file(fmt: str, path: Path) -> list[dict[str, Any]]:
    if fmt == "openvas_xml":
        return parse_openvas_xml(path)
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def parse_openvas_xml(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    records = []
    for result in tree.findall(".//result"):
        nvt = result.find("./nvt")
        record: dict[str, Any] = {
            "result_id": result.attrib.get("id"),
            "host": child_text(result, "host"),
            "port": child_text(result, "port"),
            "threat": child_text(result, "threat"),
            "severity": child_text(result, "severity"),
            "description": child_text(result, "description"),
        }
        qod_value = result.find("./qod/value")
        if qod_value is not None:
            record["qod"] = safe_text(qod_value.text)
        if nvt is not None:
            record.update(
                {
                    "nvt_oid": nvt.attrib.get("oid"),
                    "plugin_name": child_text(nvt, "name"),
                    "family": child_text(nvt, "family"),
                    "cvss_base_score": child_text(nvt, "cvss_base"),
                    "cve": child_text(nvt, "cve"),
                    "solution": child_text(nvt, "solution"),
                    "solution_type": child_text(nvt, "solution_type"),
                }
            )
        records.append(record)
    return records


def normalize_record(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    severity = openvas_severity(record.get("threat"), record.get("severity") or record.get("cvss_base_score"))
    severity_label = INT_TO_SEVERITY[severity]
    host = truncate(record.get("host") or record.get("hostname") or record.get("ip") or "unknown", 253) or "unknown"
    port, protocol = parse_openvas_port(record.get("port"), record.get("protocol"))
    nvt_oid = truncate(record.get("nvt_oid") or record.get("oid") or "unknown", 128) or "unknown"
    plugin_name = truncate(record.get("plugin_name") or record.get("name") or "Unnamed OpenVAS NVT", 256) or "Unnamed OpenVAS NVT"
    description = redact(truncate(record.get("description"), 2048))
    solution = redact(truncate(record.get("solution"), 1024))
    evidence_text = redact(truncate(record.get("evidence") or record.get("result") or record.get("details"), 2048))
    threat = truncate(record.get("threat"), 64)
    family = truncate(record.get("family") or record.get("plugin_family"), 128)
    qod = parse_percent(record.get("qod") or record.get("qod_value"))
    cvss = parse_float(record.get("cvss_base_score") or record.get("cvss") or record.get("severity"))
    cves = normalize_cves(record.get("cve"), record)
    result = {
        "type": "vulnerability_import_result",
        "host": host,
        "port": port,
        "protocol": protocol,
        "nvt_oid": nvt_oid,
        "plugin_name": plugin_name,
        "family": family,
        "threat": threat,
        "qod": qod,
        "severity": severity,
        "severity_label": severity_label,
        "cve": cves,
        "cvss_base_score": cvss,
        "description": description,
        "solution": solution,
        "solution_type": truncate(record.get("solution_type"), 64),
        "result_id": truncate(record.get("result_id"), 128),
        "evidence_text": evidence_text,
        "sources": [fmt],
        "source_count": 1,
        "source_details": [{"source": fmt, "nvt_oid": nvt_oid, "host": host, "port": port, "threat": threat}],
        "confidence": confidence_for_record(severity, qod),
        "evidence": {
            "summary": f"OpenVAS imported {severity_label} finding {plugin_name} on {host}.",
            "items": [{"evidence_text": evidence_text}] if evidence_text else [],
        },
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


def openvas_severity(threat: Any, score: Any) -> int:
    threat_text = str(threat or "").strip().lower()
    threat_severity = THREAT_TO_SEVERITY.get(threat_text)
    numeric = parse_float(score)
    if numeric is None or numeric <= 0:
        return threat_severity if threat_severity is not None else 0
    if numeric < 4.0:
        score_severity = 1
    elif numeric < 7.0:
        score_severity = 2
    elif numeric < 9.0:
        score_severity = 3
    else:
        score_severity = 4
    if threat_severity is None:
        return score_severity
    return max(threat_severity, score_severity)


def severity_int(value: Any) -> int:
    if isinstance(value, int):
        return min(max(value, 0), 4)
    text = str(value).strip().lower()
    if text.isdigit():
        return min(max(int(text), 0), 4)
    return SEVERITY_TO_INT.get(text, 0)


def confidence_for_record(severity: int, qod: int | None) -> float:
    base = {0: 0.55, 1: 0.68, 2: 0.78, 3: 0.84, 4: 0.90}.get(severity, 0.70)
    if qod is None:
        return base
    return round(min(max(base * (0.75 + (qod / 400.0)), 0.0), 0.98), 2)


def normalize_cves(value: Any, record: dict[str, Any]) -> list[str]:
    candidates = normalize_list(value)
    for field in ("description", "solution", "evidence", "result", "details"):
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
        if text and text not in result and text.upper() != "NOCVE":
            result.append(text[:128])
    return result


def parse_openvas_port(value: Any, protocol_value: Any = None) -> tuple[int | None, str | None]:
    text = safe_text(value)
    protocol = truncate(protocol_value, 32)
    if "/" in text:
        port_text, proto_text = text.split("/", 1)
        protocol = truncate(proto_text, 32)
    else:
        port_text = text
    return parse_port(port_text), protocol


def parse_port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def parse_percent(value: Any) -> int | None:
    try:
        percent = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return min(max(percent, 0), 100)


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


def child_text(element: ET.Element, tag: str) -> str | None:
    child = element.find(f"./{tag}")
    return safe_text(child.text) if child is not None else None


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
