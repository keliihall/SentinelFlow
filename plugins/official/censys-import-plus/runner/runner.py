#!/usr/bin/env python3
"""Controlled Censys-style exposure intelligence import for SentinelFlow."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "censys-import-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SOURCE_BASE_CONFIDENCE = {"fixture": 0.84, "local_cache": 0.78, "censys_api": 0.88}


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
        print(f"runner I/O failure: {safe_message(error)}", file=sys.stderr)
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
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "local_cache", "api_lookup", "hybrid"}:
        raise InputError("unsupported Censys import mode", "$.options.mode")
    lookup = object_at(options, "lookup", "$.options.lookup")
    local_cache = object_at(options, "local_cache", "$.options.local_cache")
    provider = object_at(options, "provider", "$.options.provider")
    output_options = object_at(options, "output", "$.options.output")
    query = build_query_descriptor(target, lookup)
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    if mode == "dry_run":
        return build_output(target, mode, authorization_scope, query, [], source_status, errors, 0)
    if mode == "fixture":
        observations.extend(load_file_source("fixture", string_or(local_cache.get("fixture_file"), "examples/fixture.censys.example.com.json"), query, source_status))
    if mode in {"local_cache", "hybrid"} and bool(local_cache.get("enabled")):
        observations.extend(load_file_source("local_cache", string_or(local_cache.get("cache_file"), "examples/cache.empty.json"), query, source_status))
    if mode in {"api_lookup", "hybrid"} and bool(provider.get("enabled")):
        observations.extend(run_provider_lookup(provider, query, source_status))

    max_results = bounded_int(lookup.get("max_results"), 100, 0, MAX_RESULTS)
    results = merge_results(observations)[:max_results]
    if not bool(output_options.get("include_certificate")):
        for result in results:
            result["certificate"] = {}
    if not bool(output_options.get("include_names")):
        for result in results:
            result["names"] = []
    if not bool(output_options.get("include_service_fingerprint")):
        for result in results:
            result["service_fingerprint"] = {}
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    return build_output(target, mode, authorization_scope, query, results, source_status, errors, len(observations))


def build_query_descriptor(target: dict[str, Any], lookup: dict[str, Any]) -> dict[str, Any]:
    target_type = string_at(target, "type", "$.target.type")
    target_value = string_at(target, "value", "$.target.value").strip()
    scope = string_at(lookup, "scope", "$.options.lookup.scope")
    if scope != target_type:
        raise InputError("lookup.scope must match target.type", "$.options.lookup.scope")
    if any(token in target_value for token in ['"', "'", "&&", "||", "\n", "\r", ";", "|"]):
        raise InputError("target.value contains unsupported query metacharacters", "$.target.value")
    if scope == "ip":
        try:
            ipaddress.ip_address(target_value)
        except ValueError as error:
            raise InputError("target.value must be a valid IP address for ip scope", "$.target.value") from error
    field = {
        "ip": "host.ip",
        "domain": "services.tls.certificates.leaf_data.names",
        "organization": "autonomous_system.organization",
        "certificate": "services.tls.certificates.leaf_data.fingerprint",
    }[scope]
    return {
        "scope": scope,
        "field": field,
        "value": target_value,
        "constructed_query": f"{field}: {json.dumps(target_value, ensure_ascii=True)}",
        "user_query_allowed": False,
    }


def load_file_source(source: str, path: str, query: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        observations = [observation_from_mapping(item, source) for item in data.get("results", []) if isinstance(item, dict) and matches_query(item, query)]
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_provider_lookup(provider: dict[str, Any], query: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not os.environ.get("CENSYS_API_ID") or not os.environ.get("CENSYS_API_SECRET"):
        status = "skipped_missing_secret" if bool(provider.get("allow_missing_secret")) else "error_missing_secret"
        source_status.append({"source": "censys_api", "status": status, "message": "Censys provider lookup requires configured CENSYS_API_ID and CENSYS_API_SECRET.", "query_count": 0, "probe_count": 0})
        return []
    source_status.append({"source": "censys_api", "status": "skipped_not_implemented", "message": "Censys provider facade is reserved for configured deployments; no raw query or secret is emitted.", "query_count": 0, "probe_count": 0, "query_scope": query["scope"]})
    return []


def matches_query(item: dict[str, Any], query: dict[str, Any]) -> bool:
    value = str(query["value"]).lower()
    if query["scope"] == "ip":
        return str(item.get("ip", "")).lower() == value
    if query["scope"] == "domain":
        names = item.get("names", []) if isinstance(item.get("names"), list) else []
        cert = item.get("certificate", {}) if isinstance(item.get("certificate"), dict) else {}
        cert_names = cert.get("names", []) if isinstance(cert.get("names"), list) else []
        return any(str(name).lower().endswith(value) for name in [*names, *cert_names])
    if query["scope"] == "organization":
        return value in str(item.get("organization", "")).lower()
    if query["scope"] == "certificate":
        cert = item.get("certificate", {}) if isinstance(item.get("certificate"), dict) else {}
        return value in json.dumps(cert, sort_keys=True).lower()
    return False


def observation_from_mapping(item: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "host": truncate(item.get("host")) or "",
        "ip": truncate(item.get("ip")) or "",
        "port": int(item.get("port", 0)),
        "protocol": truncate(item.get("protocol")) or "unknown",
        "service": truncate(item.get("service")),
        "names": clean_string_list(item.get("names", [])),
        "certificate": clean_certificate(item.get("certificate", {})),
        "service_fingerprint": clean_service_fingerprint(item.get("service_fingerprint", {})),
        "first_observed_at": truncate(item.get("first_observed_at")),
        "last_observed_at": truncate(item.get("last_observed_at")),
        "observed_at": truncate(item.get("observed_at")),
        "confidence": clamp_float(item.get("confidence", SOURCE_BASE_CONFIDENCE.get(source, 0.78))),
        "source": source,
        "source_type": "fixture" if source == "fixture" else "passive_intel",
        "raw": item,
    }


def merge_results(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for item in observations:
        if not item["host"] or not item["ip"] or item["port"] < 1:
            continue
        grouped.setdefault((item["host"], item["ip"], item["port"]), []).append(item)
    results = []
    for (host, ip, port), items in sorted(grouped.items()):
        selected = max(items, key=lambda item: item["confidence"])
        sources = sorted({item["source"] for item in items})
        results.append({
            "type": "exposure_intel_result",
            "host": host,
            "ip": ip,
            "port": port,
            "protocol": selected["protocol"],
            "service": selected["service"],
            "names": sorted({name for item in items for name in item["names"]}),
            "certificate": selected["certificate"],
            "service_fingerprint": selected["service_fingerprint"],
            "first_observed_at": selected["first_observed_at"],
            "last_observed_at": selected["last_observed_at"],
            "observed_at": selected["observed_at"],
            "sources": sources,
            "source_count": len(sources),
            "source_details": [{"source": item["source"], "source_type": item["source_type"], "evidence": item["raw"]} for item in items],
            "confidence": min(selected["confidence"] + 0.04 * (len(sources) - 1), 0.98),
            "evidence": {"summary": f"Censys exposure intelligence observed {host}:{port}/{selected['protocol']}.", "items": []},
        })
    return results


def build_output(target: dict[str, Any], mode: str, authorization_scope: str, query: dict[str, Any], results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], observation_count: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": target.get("type"), "value": target.get("value")},
        "mode": mode,
        "query": query,
        "results": results[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "observation_count": observation_count,
            "result_count": len(results),
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
            "user_query_allowed": False,
            "raw_query_from_user": False,
            "secret_emitted": False,
            "active_target_connections": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
        },
    }


def resolve_plugin_file(value: str) -> Path:
    path = Path(value)
    candidate = path if path.is_absolute() else PLUGIN_ROOT / path
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(PLUGIN_ROOT)
    if not resolved.is_file():
        raise InputError("file path must point to a regular file", "$.options.local_cache.cache_file")
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


def string_or(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def clean_certificate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    cleaned = {
        "subject": truncate(value.get("subject")),
        "issuer": truncate(value.get("issuer")),
        "fingerprint_sha256": truncate(value.get("fingerprint_sha256")),
        "names": clean_string_list(value.get("names", [])),
        "not_before": truncate(value.get("not_before")),
        "not_after": truncate(value.get("not_after")),
    }
    return {key: item for key, item in cleaned.items() if item not in (None, "", [])}


def clean_service_fingerprint(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, Any] = {}
    if value.get("jarm") is not None:
        cleaned["jarm"] = truncate(value.get("jarm"), 128)
    software = value.get("software", [])
    if isinstance(software, list):
        cleaned["software"] = [
            {"name": truncate(item.get("name"), 128), "version": truncate(item.get("version"), 128)}
            for item in software
            if isinstance(item, dict)
        ][:20]
    return cleaned


def clean_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value[:100]:
        text = truncate(item, 253)
        if text and text not in result:
            result.append(text)
    return result


def truncate(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def clamp_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(max(number, 0.0), 1.0)


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
