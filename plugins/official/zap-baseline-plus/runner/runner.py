#!/usr/bin/env python3
"""Bounded OWASP ZAP baseline report adapter for SentinelFlow."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "zap-baseline-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONFIDENCE_ORDER = {"false_positive": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}
SECRET_PATTERN = re.compile(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*\S+")
AUTH_PATTERN = re.compile(r"(?i)(authorization:\s*)(bearer|basic)\s+[^'\"\s]+")
TAG_PATTERN = re.compile(r"<[^>]+>")


class InputError(Exception):
    """Controlled input validation error."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.field = field


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        output = run(payload)
    except json.JSONDecodeError as error:
        print(f"invalid JSON input: {error}", file=sys.stderr)
        return 2
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
    if string_at(target, "type", "$.target.type") not in {"url", "domain", "report"}:
        raise InputError("target.type must be url, domain, or report", "$.target.type")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "local_file"}:
        raise InputError("unsupported ZAP adapter mode", "$.options.mode")
    import_options = object_at(options, "import", "$.options.import")
    filters = object_at(options, "filters", "$.options.filters")
    output_options = object_at(options, "output", "$.options.output")
    fmt = string_at(import_options, "format", "$.options.import.format")
    if fmt not in {"zap_json", "zap_xml"}:
        raise InputError("unsupported ZAP report format", "$.options.import.format")
    policy = object_at(payload, "policy", "$.policy")
    for key in ("allow_active_scan", "allow_ajax_spider", "allow_authentication", "allow_attack_mode"):
        if bool(policy.get(key)):
            raise InputError("active ZAP execution is not supported by this adapter", f"$.policy.{key}")

    if mode == "dry_run":
        return build_output(target, mode, fmt, authorization_scope, [], [], [], 0, 0, 0, 0)

    path = resolve_plugin_file(string_at(import_options, "file", "$.options.import.file"))
    max_records = bounded_int(import_options.get("max_records"), 1000, 0, MAX_RESULTS)
    minimum_risk = normalized_choice(filters.get("minimum_risk"), RISK_ORDER, "$.options.filters.minimum_risk")
    minimum_confidence = normalized_choice(
        filters.get("minimum_confidence"), CONFIDENCE_ORDER, "$.options.filters.minimum_confidence"
    )
    raw_records = parse_json(path) if fmt == "zap_json" else parse_xml(path)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped = 0
    seen: set[tuple[str, str, str, str]] = set()
    for raw in raw_records:
        if len(results) >= max_records:
            break
        normalized = normalize_record(raw, fmt)
        skip_reason = filter_reason(normalized, minimum_risk, minimum_confidence, bool(filters.get("include_false_positives")))
        if skip_reason:
            skipped += 1
            if len(errors) < MAX_ERRORS:
                errors.append({"code": "AlertFiltered", "message": skip_reason, "field": "$.options.filters", "alert_id": normalized["alert_id"]})
            continue
        key = (normalized["alert_id"], normalized["url"], normalized.get("method") or "", normalized.get("parameter") or "")
        if bool(output_options.get("deduplicate")) and key in seen:
            skipped += 1
            continue
        seen.add(key)
        if not bool(output_options.get("include_attack")):
            normalized["attack"] = None
        if not bool(output_options.get("include_evidence")):
            normalized["evidence_text"] = None
            normalized["evidence"]["items"] = []
        if not bool(output_options.get("include_source_details")):
            normalized["source_details"] = []
        results.append(normalized)

    source_status = [{
        "source": fmt,
        "status": "ok",
        "message": f"{fmt} baseline report imported with passive offline controls.",
        "query_count": 0,
        "probe_count": 0,
        "record_count": len(raw_records),
        "skipped_count": skipped,
    }]
    return build_output(
        target, mode, fmt, authorization_scope, results, source_status, errors,
        len(raw_records), len(results), skipped, count_sites(raw_records)
    )


def parse_json(path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise InputError(f"invalid ZAP JSON report: {error}", "$.options.import.file") from error
    sites = document.get("site", []) if isinstance(document, dict) else []
    if isinstance(sites, dict):
        sites = [sites]
    records = []
    for site_index, site in enumerate(sites):
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances", []) or [{}]
            if isinstance(instances, dict):
                instances = [instances]
            for instance in instances:
                records.append({"site": site, "site_index": site_index, "alert": alert, "instance": instance if isinstance(instance, dict) else {}})
    return records


def parse_xml(path: Path) -> list[dict[str, Any]]:
    content = path.read_bytes()
    if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise InputError("XML document type and entity declarations are not allowed", "$.options.import.file")
    root = ET.fromstring(content)
    records = []
    for site_index, site in enumerate(root.findall(".//site")):
        for alert in site.findall("./alerts/alertitem"):
            instances = alert.findall("./instances/instance") or [ET.Element("instance")]
            for instance in instances:
                records.append({
                    "site": {"@name": site.get("name"), "@host": site.get("host"), "@port": site.get("port"), "@ssl": site.get("ssl")},
                    "site_index": site_index,
                    "alert": {child.tag: child.text for child in alert if child.tag not in {"instances"}},
                    "instance": {child.tag: child.text for child in instance},
                })
    return records


def normalize_record(record: dict[str, Any], fmt: str) -> dict[str, Any]:
    site = record["site"]
    alert = record["alert"]
    instance = record["instance"]
    alert_id = text(alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef") or "unknown", 64) or "unknown"
    alert_ref = text(alert.get("alertRef") or alert.get("alertref"), 64)
    alert_name = clean_text(alert.get("alert") or alert.get("name") or f"ZAP alert {alert_id}", 256) or f"ZAP alert {alert_id}"
    risk = normalize_risk(alert.get("riskcode"), alert.get("riskdesc") or alert.get("risk"))
    confidence_label = normalize_confidence(alert.get("confidence"))
    url = text(instance.get("uri") or instance.get("url") or site.get("@name") or site.get("name") or "unknown", 2048) or "unknown"
    method = text(instance.get("method"), 16)
    parameter = clean_text(instance.get("param") or instance.get("parameter"), 256)
    description = redact(clean_text(alert.get("desc") or alert.get("description"), 4096))
    solution = redact(clean_text(alert.get("solution"), 4096))
    other_info = redact(clean_text(instance.get("otherinfo") or alert.get("otherinfo"), 2048))
    attack = redact_auth(redact(clean_text(instance.get("attack"), 2048)))
    evidence_text = redact_auth(redact(clean_text(instance.get("evidence"), 2048)))
    source_id = text(alert.get("sourceid") or alert.get("sourceId"), 64)
    return {
        "type": "zap_alert_result",
        "url": url,
        "site": text(site.get("@name") or site.get("name"), 2048),
        "host": text(site.get("@host") or site.get("host"), 512),
        "port": parse_int(site.get("@port") or site.get("port")),
        "ssl": parse_bool(site.get("@ssl") or site.get("ssl")),
        "alert_id": alert_id,
        "alert_ref": alert_ref,
        "alert_name": alert_name,
        "risk": risk,
        "risk_description": clean_text(alert.get("riskdesc") or alert.get("risk"), 256),
        "confidence_label": confidence_label,
        "method": method,
        "parameter": parameter,
        "attack": attack,
        "evidence_text": evidence_text,
        "description": description,
        "other_info": other_info,
        "solution": solution,
        "reference": normalize_references(alert.get("reference")),
        "cwe_id": parse_int(alert.get("cweid") or alert.get("cweId")),
        "wasc_id": parse_int(alert.get("wascid") or alert.get("wascId")),
        "source_id": source_id,
        "sources": [fmt],
        "source_count": 1,
        "source_details": [{"source": fmt, "site_index": record["site_index"], "alert_id": alert_id, "source_id": source_id}],
        "confidence": confidence_score(confidence_label),
        "evidence": {
            "summary": f"ZAP imported {risk} passive alert {alert_id} on {url}.",
            "items": [{"method": method, "parameter": parameter, "evidence": evidence_text}],
        },
    }


def filter_reason(result: dict[str, Any], minimum_risk: str, minimum_confidence: str, include_false_positives: bool) -> str | None:
    if result["confidence_label"] == "false_positive" and not include_false_positives:
        return "false-positive alert excluded"
    if RISK_ORDER[result["risk"]] < RISK_ORDER[minimum_risk]:
        return f"alert risk {result['risk']} is below minimum {minimum_risk}"
    if CONFIDENCE_ORDER[result["confidence_label"]] < CONFIDENCE_ORDER[minimum_confidence]:
        return f"alert confidence {result['confidence_label']} is below minimum {minimum_confidence}"
    return None


def build_output(
    target: dict[str, Any], mode: str, fmt: str, authorization_scope: str,
    results: list[dict[str, Any]], source_status: list[dict[str, Any]],
    errors: list[dict[str, Any]], imported_count: int, result_count: int,
    skipped_count: int, site_count: int,
) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "format": fmt,
        "results": results[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "site_count": site_count,
            "imported_record_count": imported_count,
            "result_count": result_count,
            "skipped_record_count": skipped_count,
            "requires_active_scan": False,
            "requires_approval": False,
            "source_status_count": len(source_status),
            "error_count": len(errors),
            "authorization_scope": authorization_scope,
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "authorization_scope_required": True,
            "offline_import_only": True,
            "passive_results_only": True,
            "active_target_connections": 0,
            "scanner_invocations": 0,
            "active_scan_invocations": 0,
            "ajax_spider_invocations": 0,
            "attack_mode": False,
            "credential_use": False,
            "secret_redaction_enabled": True,
        },
    }


def normalize_risk(code: Any, label: Any) -> str:
    coded = {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(code).strip())
    if coded is not None:
        return coded
    text_value = str(label or "").strip().lower()
    text_value = text_value.split("(", 1)[0].strip()
    for name in ("high", "medium", "low", "informational", "info"):
        if name in text_value:
            return "info" if name in {"informational", "info"} else name
    return "info"


def normalize_confidence(value: Any) -> str:
    text_value = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {"0": "false_positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
    if text_value in CONFIDENCE_ORDER:
        return text_value
    for name in ("false_positive", "confirmed", "high", "medium", "low"):
        if name in text_value:
            return name
    return aliases.get(text_value, "medium")


def confidence_score(label: str) -> float:
    return {"false_positive": 0.10, "low": 0.45, "medium": 0.70, "high": 0.88, "confirmed": 0.96}[label]


def normalized_choice(value: Any, choices: dict[str, int], field: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in choices:
        raise InputError(f"value must be one of {', '.join(choices)}", field)
    return normalized


def count_sites(records: list[dict[str, Any]]) -> int:
    return len({record["site_index"] for record in records})


def normalize_references(value: Any) -> list[str]:
    raw = TAG_PATTERN.sub(" ", str(value or ""))
    results = []
    for item in re.split(r"[\r\n]+", raw):
        candidate = item.strip()[:1024]
        if candidate and candidate not in results:
            results.append(candidate)
    return results[:32]


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


def text(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "").strip()[:limit]


def clean_text(value: Any, limit: int = 512) -> str | None:
    candidate = text(value, limit * 2)
    if candidate is None:
        return None
    return re.sub(r"\s+", " ", TAG_PATTERN.sub(" ", candidate)).strip()[:limit]


def parse_int(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def parse_bool(value: Any) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_PATTERN.sub(lambda match: match.group(1) + "=[REDACTED]", value)


def redact_auth(value: str | None) -> str | None:
    if value is None:
        return None
    return AUTH_PATTERN.sub(lambda match: match.group(1) + match.group(2) + " [REDACTED]", value)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
