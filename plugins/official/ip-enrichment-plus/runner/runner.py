#!/usr/bin/env python3
"""Passive IP enrichment and local address classification for SentinelFlow."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "ip-enrichment-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SOURCE_BASE_CONFIDENCE = {"local_classifier": 0.70, "fixture": 0.82, "local_cache": 0.78, "ipinfo": 0.86, "maxmind": 0.84, "cloud_ranges": 0.80}


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
    if mode not in {"fixture", "dry_run", "local_cache", "provider_lookup", "hybrid"}:
        raise InputError("unsupported IP enrichment mode", "$.options.mode")
    if string_at(target, "type", "$.target.type") != "ip":
        raise InputError("target.type must be ip", "$.target.type")
    ip = parse_ip(string_at(target, "value", "$.target.value"))
    lookup = object_at(options, "lookup", "$.options.lookup")
    local_cache = object_at(options, "local_cache", "$.options.local_cache")
    provider = object_at(options, "provider", "$.options.provider")
    output_options = object_at(options, "output", "$.options.output")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = [local_classification(ip)]

    if mode == "fixture":
        observations.extend(load_file_source("fixture", string_or(local_cache.get("fixture_file"), "examples/fixture.ip.example.json"), ip, source_status))
    if mode in {"local_cache", "hybrid"} and bool(local_cache.get("enabled")):
        observations.extend(load_file_source("local_cache", string_or(local_cache.get("cache_file"), "examples/cache.empty.json"), ip, source_status))
    if mode in {"provider_lookup", "hybrid"} and bool(provider.get("enabled")):
        observations.extend(run_provider_lookup(provider, ip, source_status))
    if mode == "dry_run":
        source_status.append({"source": "local_classifier", "status": "ok", "message": "local IP classification completed.", "query_count": 0, "probe_count": 0})

    max_results = bounded_int(lookup.get("max_results"), 100, 0, MAX_RESULTS)
    results = merge_results(observations, ip)[:max_results]
    if not bool(output_options.get("include_geo")):
        for result in results:
            result["geo"] = {}
    if not bool(output_options.get("include_cloud")):
        for result in results:
            result["cloud"] = {}
    if not bool(output_options.get("include_cdn_waf")):
        for result in results:
            result["cdn_waf"] = {}
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    return build_output(ip, mode, authorization_scope, results, source_status, errors, len(observations))


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise InputError("target.value must be a valid IP address", "$.target.value") from error


def local_classification(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, Any]:
    classification = classify_ip(ip)
    return {
        "ip": str(ip),
        "ip_version": ip.version,
        "classification": classification,
        "is_public": classification == "public",
        "asn": None,
        "organization": None,
        "isp": None,
        "geo": {},
        "cloud": {"provider": None, "service": None, "region": None, "confidence": 0.0},
        "cdn_waf": {"cdn": False, "waf": False, "provider": None, "signals": [], "confidence": 0.0},
        "observed_at": None,
        "confidence": SOURCE_BASE_CONFIDENCE["local_classifier"],
        "source": "local_classifier",
        "source_type": "local",
        "raw": {"classification": classification},
    }


def classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public" if ip.is_global else "special"


def load_file_source(source: str, path: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        observations = [observation_from_mapping(item, source) for item in data.get("results", []) if isinstance(item, dict) and str(item.get("ip", "")).strip() == str(ip)]
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_provider_lookup(provider: dict[str, Any], ip: ipaddress.IPv4Address | ipaddress.IPv6Address, source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    sources = provider.get("sources", [])
    if not isinstance(sources, list):
        sources = []
    for source in sources:
        if source == "ipinfo" and not os.environ.get("IPINFO_TOKEN"):
            status = "skipped_missing_secret" if bool(provider.get("allow_missing_secret")) else "error_missing_secret"
            source_status.append({"source": "ipinfo", "status": status, "message": "IPInfo provider requires configured IPINFO_TOKEN.", "query_count": 0, "probe_count": 0})
        elif source == "maxmind" and not os.environ.get("MAXMIND_LICENSE_KEY"):
            status = "skipped_missing_secret" if bool(provider.get("allow_missing_secret")) else "error_missing_secret"
            source_status.append({"source": "maxmind", "status": status, "message": "MaxMind provider requires configured MAXMIND_LICENSE_KEY.", "query_count": 0, "probe_count": 0})
        elif source == "cloud_ranges":
            source_status.append({"source": "cloud_ranges", "status": "skipped_not_implemented", "message": "Cloud range provider facade is reserved for configured deployments.", "query_count": 0, "probe_count": 0, "query_ip": str(ip)})
        else:
            source_status.append({"source": str(source), "status": "skipped_not_implemented", "message": "Provider facade is reserved for configured deployments; no secret or raw query is emitted.", "query_count": 0, "probe_count": 0, "query_ip": str(ip)})
    return observations


def observation_from_mapping(item: dict[str, Any], source: str) -> dict[str, Any]:
    ip = parse_ip(str(item.get("ip", "")))
    classification = classify_ip(ip)
    return {
        "ip": str(ip),
        "ip_version": ip.version,
        "classification": classification,
        "is_public": classification == "public",
        "asn": int(item["asn"]) if isinstance(item.get("asn"), int) else None,
        "organization": truncate(item.get("organization")),
        "isp": truncate(item.get("isp")),
        "geo": clean_mapping(item.get("geo", {})),
        "cloud": clean_cloud(item.get("cloud", {})),
        "cdn_waf": clean_cdn_waf(item.get("cdn_waf", {})),
        "observed_at": truncate(item.get("observed_at")),
        "confidence": clamp_float(item.get("confidence", SOURCE_BASE_CONFIDENCE.get(source, 0.78))),
        "source": source,
        "source_type": "fixture" if source == "fixture" else "passive_intel",
        "raw": item,
    }


def merge_results(observations: list[dict[str, Any]], ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[dict[str, Any]]:
    if not observations:
        return []
    selected = max(observations, key=lambda item: item.get("confidence", 0.0))
    local = observations[0]
    sources = sorted({item["source"] for item in observations})
    result = {
        "type": "ip_enrichment_result",
        "ip": str(ip),
        "ip_version": ip.version,
        "classification": local["classification"],
        "is_public": local["is_public"],
        "asn": first_present(observations, "asn"),
        "organization": first_present(observations, "organization"),
        "isp": first_present(observations, "isp"),
        "geo": first_mapping(observations, "geo"),
        "cloud": first_mapping(observations, "cloud"),
        "cdn_waf": first_mapping(observations, "cdn_waf"),
        "observed_at": first_present(observations, "observed_at"),
        "sources": sources,
        "source_count": len(sources),
        "source_details": [{"source": item["source"], "source_type": item["source_type"], "evidence": item["raw"]} for item in observations],
        "confidence": min(float(selected.get("confidence", 0.0)) + 0.03 * (len(sources) - 1), 0.98),
        "evidence": {"summary": f"IP enrichment classified {ip} as {local['classification']}.", "items": []},
    }
    return [result]


def build_output(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, mode: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], observation_count: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": "ip", "value": str(ip)},
        "mode": mode,
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
            "secret_emitted": False,
            "active_target_connections": 0,
            "dns_queries": 0,
            "port_scan_attempts": 0,
            "exploit_attempts": 0,
        },
    }


def first_present(items: list[dict[str, Any]], field: str) -> Any:
    for item in items:
        value = item.get(field)
        if value not in (None, "", []):
            return value
    return None


def first_mapping(items: list[dict[str, Any]], field: str) -> dict[str, Any]:
    for item in items:
        value = item.get(field)
        if isinstance(value, dict) and meaningful_mapping(value):
            return value
    return {}


def meaningful_mapping(value: dict[str, Any]) -> bool:
    for item in value.values():
        if item not in (None, "", [], {}, False, 0, 0.0):
            return True
    return False


def clean_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key)[:128]: item for key, item in value.items() if item is not None}


def clean_cloud(value: Any) -> dict[str, Any]:
    base = {"provider": None, "service": None, "region": None, "confidence": 0.0}
    if isinstance(value, dict):
        base.update({key: value.get(key) for key in base if key in value})
    base["confidence"] = clamp_float(base.get("confidence", 0.0))
    return base


def clean_cdn_waf(value: Any) -> dict[str, Any]:
    base = {"cdn": False, "waf": False, "provider": None, "signals": [], "confidence": 0.0}
    if isinstance(value, dict):
        base["cdn"] = bool(value.get("cdn"))
        base["waf"] = bool(value.get("waf"))
        base["provider"] = truncate(value.get("provider"))
        signals = value.get("signals", [])
        base["signals"] = [str(item)[:128] for item in signals[:20]] if isinstance(signals, list) else []
        base["confidence"] = clamp_float(value.get("confidence", 0.0))
    return base


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
