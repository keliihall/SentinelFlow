#!/usr/bin/env python3
"""Bounded CMDB import and writeback reconciliation for SentinelFlow."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "cmdb-sync-plus"
MAX_RESULTS = 10000
MAX_ERRORS = 50
CANONICAL_FIELDS = {
    "asset_type", "name", "addresses", "department", "business_system", "owner",
    "criticality", "status", "source_refs", "last_seen_at",
}
SECRET_PATTERN = re.compile(r"(?i)(password|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+")


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
    if string_at(target, "type", "$.target.type") != "cmdb":
        raise InputError("target.type must be cmdb", "$.target.type")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "import", "reconcile", "writeback_plan"}:
        raise InputError("unsupported CMDB sync mode", "$.options.mode")
    cmdb_options = object_at(options, "cmdb", "$.options.cmdb")
    sentinelflow_options = object_at(options, "sentinelflow", "$.options.sentinelflow")
    mapping = validate_mapping(object_at(options, "mapping", "$.options.mapping"))
    writeback = object_at(options, "writeback", "$.options.writeback")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")
    for key in ("allow_network", "allow_credentials", "allow_direct_writeback", "allow_delete"):
        if bool(policy.get(key)):
            raise InputError("network, credential, direct writeback, and delete operations are not supported", f"$.policy.{key}")
    validate_writeback(writeback)

    if mode == "dry_run":
        return build_output(target, mode, authorization_scope, [], [], [], [], 0, 0)

    cmdb_rows = load_cmdb(cmdb_options)
    results = [normalize_cmdb(row, mapping, index) for index, row in enumerate(cmdb_rows)]
    operations: list[dict[str, Any]] = []
    source_status = [{
        "source": "cmdb_inventory",
        "status": "ok",
        "message": f"{len(results)} CMDB assets imported.",
        "record_count": len(results),
        "query_count": 0,
        "write_count": 0,
    }]

    sf_assets: list[dict[str, Any]] = []
    if mode in {"reconcile", "writeback_plan"}:
        sf_assets = load_sentinelflow(sentinelflow_options)
        operations = reconcile(results, sf_assets, writeback)
        if not bool(output_options.get("include_noop_operations")):
            operations = [item for item in operations if item["action"] != "noop"]
        source_status.append({
            "source": "sentinelflow_normalized_assets",
            "status": "ok",
            "message": f"{len(sf_assets)} normalized SentinelFlow assets loaded.",
            "record_count": len(sf_assets),
            "query_count": 0,
            "write_count": 0,
        })

    max_records = bounded_int(output_options.get("max_records"), 1000, 0, MAX_RESULTS)
    results = results[:max_records]
    operations = operations[:max_records]
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    return build_output(
        target, mode, authorization_scope, results, operations, source_status, [],
        len(cmdb_rows), len(sf_assets),
    )


def load_cmdb(options: dict[str, Any]) -> list[dict[str, Any]]:
    fmt = string_at(options, "format", "$.options.cmdb.format")
    path = resolve_plugin_file(string_at(options, "file", "$.options.cmdb.file"), "$.options.cmdb.file")
    if fmt == "json":
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, list):
            rows = document
        elif isinstance(document, dict):
            rows = next((document[key] for key in ("assets", "items", "results", "data") if isinstance(document.get(key), list)), [])
        else:
            rows = []
        return [item for item in rows if isinstance(item, dict)]
    if fmt == "csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    raise InputError("unsupported CMDB format", "$.options.cmdb.format")


def load_sentinelflow(options: dict[str, Any]) -> list[dict[str, Any]]:
    if string_at(options, "format", "$.options.sentinelflow.format") != "normalized_json":
        raise InputError("unsupported SentinelFlow asset format", "$.options.sentinelflow.format")
    path = resolve_plugin_file(
        string_at(options, "file", "$.options.sentinelflow.file"),
        "$.options.sentinelflow.file",
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    values = document if isinstance(document, list) else document.get("assets", []) if isinstance(document, dict) else []
    return [normalize_sentinelflow(item, index) for index, item in enumerate(values) if isinstance(item, dict)]


def normalize_cmdb(row: dict[str, Any], mapping: dict[str, str], index: int) -> dict[str, Any]:
    external_id = field_text(row, mapping["external_id"]) or f"cmdb-row-{index}"
    name = field_text(row, mapping["name"]) or external_id
    addresses = split_values(row.get(mapping["addresses"]))
    criticality = normalize_criticality(row.get(mapping["criticality"]))
    status = field_text(row, mapping["status"]) or "unknown"
    result = {
        "type": "cmdb_asset_result",
        "external_id": external_id,
        "asset_type": field_text(row, mapping["asset_type"]) or "unknown",
        "name": name,
        "addresses": addresses,
        "department": field_text(row, mapping["department"]),
        "business_system": field_text(row, mapping["business_system"]),
        "owner": redact(field_text(row, mapping["owner"])),
        "criticality": criticality,
        "status": status,
        "updated_at": field_text(row, mapping["updated_at"]),
        "sources": ["cmdb_inventory"],
        "source_count": 1,
        "source_details": [{"source": "cmdb_inventory", "external_id": external_id}],
        "confidence": 0.95,
        "evidence": {
            "summary": f"CMDB asset {name} ({external_id}) imported with ownership metadata.",
            "items": [{"department": field_text(row, mapping["department"]), "business_system": field_text(row, mapping["business_system"])}],
        },
    }
    return result


def normalize_sentinelflow(row: dict[str, Any], index: int) -> dict[str, Any]:
    external_id = text(row.get("external_id") or row.get("resource_id") or row.get("asset_id"))
    name = text(row.get("name") or row.get("hostname") or row.get("value")) or external_id or f"sentinelflow-{index}"
    addresses = split_values(row.get("addresses") or row.get("public_ips") or row.get("ip") or row.get("value"))
    return {
        "external_id": external_id,
        "asset_type": text(row.get("asset_type") or row.get("resource_type") or row.get("type")) or "unknown",
        "name": name,
        "addresses": addresses,
        "department": text(row.get("department")),
        "business_system": text(row.get("business_system")),
        "owner": redact(text(row.get("owner"))),
        "criticality": normalize_criticality(row.get("criticality")),
        "status": text(row.get("status")) or "active",
        "source_refs": clean_list(row.get("source_refs") or row.get("sources")),
        "last_seen_at": text(row.get("last_seen_at") or row.get("observed_at")),
    }


def reconcile(cmdb_assets: list[dict[str, Any]], sf_assets: list[dict[str, Any]], options: dict[str, Any]) -> list[dict[str, Any]]:
    match_fields = options.get("match_fields", [])
    allowed_fields = set(options.get("allowed_fields", []))
    policy = str(options.get("conflict_policy"))
    operations = []
    for asset in sf_assets:
        matches = [item for item in cmdb_assets if assets_match(item, asset, match_fields)]
        if len(matches) > 1:
            operations.append(operation("manual_review", asset, {}, "multiple CMDB records match this asset", matches))
            continue
        if not matches:
            action = "create" if bool(options.get("create_missing")) else "skip"
            changes = projected_changes(asset, allowed_fields) if action == "create" else {}
            operations.append(operation(action, asset, changes, "asset is absent from CMDB", []))
            continue
        current = matches[0]
        changes = diff_fields(current, asset, allowed_fields)
        if not changes:
            operations.append(operation("noop", asset, {}, "CMDB record already matches allowed fields", matches))
        elif not bool(options.get("update_existing")):
            operations.append(operation("skip", asset, {}, "updates are disabled", matches))
        elif policy == "cmdb_wins":
            operations.append(operation("noop", asset, {}, "CMDB wins conflict policy", matches))
        elif policy == "manual_review":
            operations.append(operation("manual_review", asset, changes, "differences require manual review", matches))
        else:
            operations.append(operation("update", asset, changes, "SentinelFlow wins allowed field conflicts", matches))
    return operations


def assets_match(cmdb: dict[str, Any], asset: dict[str, Any], fields: list[str]) -> bool:
    for field in fields:
        if field == "external_id" and asset.get("external_id") and cmdb.get("external_id") == asset.get("external_id"):
            return True
        if field == "name" and asset.get("name") and str(cmdb.get("name", "")).lower() == str(asset["name"]).lower():
            return True
        if field == "address" and set(cmdb.get("addresses", [])) & set(asset.get("addresses", [])):
            return True
    return False


def diff_fields(current: dict[str, Any], desired: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    result = {}
    for field in sorted(allowed):
        desired_value = desired.get(field)
        if desired_value not in (None, "", []) and current.get(field) != desired_value:
            result[field] = {"from": current.get(field), "to": desired_value}
    return result


def projected_changes(asset: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    return {field: {"from": None, "to": asset.get(field)} for field in sorted(allowed) if asset.get(field) not in (None, "", [])}


def operation(action: str, asset: dict[str, Any], changes: dict[str, Any], reason: str, matches: list[dict[str, Any]]) -> dict[str, Any]:
    match = {
        "external_id": asset.get("external_id"),
        "name": asset.get("name"),
        "addresses": asset.get("addresses", []),
    }
    digest = hashlib.sha256(json.dumps({"action": action, "match": match, "changes": changes}, sort_keys=True).encode()).hexdigest()
    return {
        "operation_id": f"cmdb-op-{digest[:20]}",
        "action": action,
        "match": match,
        "changes": changes,
        "preconditions": {
            "matched_record_count": len(matches),
            "expected_external_id": matches[0]["external_id"] if len(matches) == 1 else None,
            "delete_allowed": False,
        },
        "requires_gateway_write": action in {"create", "update"},
        "reason": reason,
    }


def build_output(
    target: dict[str, Any], mode: str, authorization_scope: str,
    results: list[dict[str, Any]], operations: list[dict[str, Any]],
    statuses: list[dict[str, Any]], errors: list[dict[str, Any]],
    cmdb_count: int, sentinelflow_count: int,
) -> dict[str, Any]:
    counts = {action: sum(1 for item in operations if item["action"] == action) for action in ("create", "update", "noop", "manual_review", "skip")}
    gateway_apply_required = any(item["requires_gateway_write"] for item in operations)
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "results": results[:MAX_RESULTS],
        "operations": operations[:MAX_RESULTS],
        "source_status": statuses[:MAX_ERRORS],
        "summary": {
            "cmdb_asset_count": cmdb_count,
            "sentinelflow_asset_count": sentinelflow_count,
            "result_count": len(results),
            "operation_count": len(operations),
            "operation_counts": counts,
            "direct_write_count": 0,
            "requires_gateway_apply": gateway_apply_required,
            "requires_approval": gateway_apply_required,
            "error_count": len(errors),
            "authorization_scope": authorization_scope,
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "authorization_scope_required": True,
            "offline_reconciliation_only": True,
            "network_requests": 0,
            "credential_use": False,
            "direct_cmdb_writes": 0,
            "delete_operations": 0,
            "gateway_apply_required": gateway_apply_required,
            "idempotency_keys_generated": True,
            "secret_redaction_enabled": True,
            "file_boundary_enforced": True,
        },
    }


def validate_mapping(value: dict[str, Any]) -> dict[str, str]:
    result = {}
    for field in ("external_id", "asset_type", "name", "addresses", "department", "business_system", "owner", "criticality", "status", "updated_at"):
        result[field] = string_at(value, field, f"$.options.mapping.{field}")
    return result


def validate_writeback(value: dict[str, Any]) -> None:
    match_fields = value.get("match_fields")
    allowed_fields = value.get("allowed_fields")
    if not isinstance(match_fields, list) or not match_fields or not set(match_fields).issubset({"external_id", "name", "address"}):
        raise InputError("invalid writeback match fields", "$.options.writeback.match_fields")
    if not isinstance(allowed_fields, list) or not set(allowed_fields).issubset(CANONICAL_FIELDS):
        raise InputError("invalid writeback allowed fields", "$.options.writeback.allowed_fields")
    if value.get("conflict_policy") not in {"cmdb_wins", "sentinelflow_wins", "manual_review"}:
        raise InputError("invalid conflict policy", "$.options.writeback.conflict_policy")


def resolve_plugin_file(value: str, field: str) -> Path:
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else PLUGIN_ROOT / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise InputError("file must exist below plugin root", field) from error
    try:
        resolved.relative_to(PLUGIN_ROOT)
    except ValueError as error:
        raise InputError("file must stay below plugin root", field) from error
    if not resolved.is_file() or resolved.stat().st_size > 4_194_304:
        raise InputError("file must be regular and no larger than 4 MiB", field)
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
    return value.strip()


def field_text(row: dict[str, Any], field: str) -> str | None:
    return text(row.get(field))


def split_values(value: Any) -> list[str]:
    if isinstance(value, list):
        candidates = value
    else:
        candidates = re.split(r"[,;|\s]+", str(value or ""))
    return clean_list(candidates)


def clean_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        candidate = text(item)
        if candidate and candidate not in result:
            result.append(candidate)
    return result[:128]


def normalize_criticality(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    aliases = {"p0": "critical", "p1": "high", "p2": "medium", "p3": "low", "重要": "high", "核心": "critical", "一般": "low"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"unknown", "low", "medium", "high", "critical"} else "unknown"


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def text(value: Any, limit: int = 2048) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "").strip()[:limit]


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    return SECRET_PATTERN.sub(lambda match: match.group(1) + "=[REDACTED]", value)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
