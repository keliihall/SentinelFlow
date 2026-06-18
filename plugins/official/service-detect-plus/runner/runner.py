#!/usr/bin/env python3
"""Passive-intel-first service detection runner for SentinelFlow."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from sources import active_safe, external_fingerprint, local_cache, passive_service_cache, upstream_findings


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "service-detect-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
PASSIVE_SOURCES = {
    "fixture",
    "local_cache",
    "upstream_port_result",
    "upstream_dns_result",
    "passive_service_cache",
    "fofa_enrichment",
    "shodan_enrichment",
    "external_fingerprint_intel",
}
ACTIVE_PROFILES = {"tcp_banner", "tls_hello", "http_head", "http_get_root", "standard_probe"}
SOURCE_BASE_CONFIDENCE = {
    "fixture": 0.70,
    "local_cache": 0.70,
    "upstream_port_result": 0.80,
    "upstream_dns_result": 0.55,
    "passive_service_cache": 0.75,
    "fofa_enrichment": 0.80,
    "shodan_enrichment": 0.85,
    "external_fingerprint_intel": 0.80,
    "tcp_banner": 0.80,
    "tls_hello": 0.85,
    "http_head": 0.85,
    "http_get_root": 0.82,
    "standard_probe": 0.90,
    "deep_probe": 0.92,
    "external_fingerprint": 0.85,
}
SOURCE_TYPES = {
    "fixture": "fixture",
    "local_cache": "passive_intel",
    "upstream_port_result": "passive_intel",
    "upstream_dns_result": "passive_intel",
    "passive_service_cache": "passive_intel",
    "fofa_enrichment": "passive_intel",
    "shodan_enrichment": "passive_intel",
    "external_fingerprint_intel": "passive_intel",
    "tcp_banner": "active",
    "tls_hello": "active",
    "http_head": "active",
    "http_get_root": "active",
    "standard_probe": "active",
    "deep_probe": "active",
    "external_fingerprint": "active",
}
SENSITIVE_HEADER_RE = re.compile(r"(?i)(authorization|cookie|set-cookie|x-api-key|token):\s*[^\r\n]+")


class InputError(Exception):
    """Controlled input validation error."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.field = field


class RateLimiter:
    """Simple process-local rate limiter."""

    def __init__(self, rate_per_second: int) -> None:
        self.interval = 1.0 / max(1, rate_per_second)
        self.next_at = time.monotonic()

    def wait(self) -> None:
        now = time.monotonic()
        if now < self.next_at:
            time.sleep(self.next_at - now)
        self.next_at = max(now, self.next_at) + self.interval


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
    authorization_scope = context.get("authorization_scope")
    if not isinstance(authorization_scope, str) or not authorization_scope.strip():
        raise InputError("context.authorization_scope is required", "$.context.authorization_scope")

    target = object_at(payload, "target", "$.target")
    if target.get("type") != "service":
        raise InputError("target.type must be service", "$.target.type")
    target_value = string_at(target, "value", "$.target.value")

    inputs = object_at(payload, "inputs", "$.inputs")
    services = validate_services(inputs.get("services", []))
    upstream_driven = "findings" in inputs
    upstream_services = validate_services(upstream_findings.extract(payload))
    if upstream_services:
        services = merge_services(services, upstream_services)
    if not services and not upstream_driven:
        service = service_from_target(target_value)
        if service:
            services = [service]
    if not services and not upstream_driven:
        raise InputError("at least one service target is required", "$.inputs.services")

    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "active", "hybrid"}:
        raise InputError("unsupported service detection mode", "$.options.mode")
    detection_depth = string_at(options, "detection_depth", "$.options.detection_depth")
    if detection_depth not in {"fixture", "passive", "safe", "standard", "deep", "external_fingerprint"}:
        raise InputError("unsupported detection_depth", "$.options.detection_depth")
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    merge_options = object_at(options, "merge", "$.options.merge")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")

    if mode == "dry_run":
        return dry_run_output(target_value, services, options, policy)

    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    active_enabled = bool(active_options.get("enabled"))
    active_requested = mode == "active" or (mode == "hybrid" and active_enabled)
    high_risk_requested = detection_depth in {"deep", "external_fingerprint"}
    if active_requested and not bool(policy.get("allow_active_verify")):
        errors.append(standard_error("PolicyDenied", "active service detection requires policy.allow_active_verify=true", "$.policy.allow_active_verify", {"mode": mode, "activeEnabled": active_enabled}))
    if active_requested and high_risk_requested:
        if not bool(policy.get("allow_high_risk")):
            errors.append(standard_error("PolicyDenied", "deep or external fingerprint detection requires policy.allow_high_risk=true", "$.policy.allow_high_risk", {"detection_depth": detection_depth}))
        if not bool(options.get("risk_acknowledged")):
            errors.append(standard_error("PolicyDenied", "deep or external fingerprint detection requires options.risk_acknowledged=true", "$.options.risk_acknowledged", {"detection_depth": detection_depth}))
        if options.get("execution_profile") not in {"authorized_assessment", "lab"}:
            errors.append(standard_error("ApprovalRequired", "high-risk detection requires authorized_assessment or lab execution_profile", "$.options.execution_profile", {"detection_depth": detection_depth}))
    if not external_fingerprint.validate_external_tool_config(active_options.get("external_fingerprint")):
        errors.append(standard_error("InputRejected", "external_fingerprint accepts only allowlisted tool/profile configuration", "$.options.active.external_fingerprint", {}))

    max_services = bounded_int(active_options.get("max_services"), 50, 1, 500)
    max_probes = bounded_int(active_options.get("max_probes_per_service"), 3, 1, 10)
    if len(services) > max_services:
        errors.append(standard_error("InputLimitExceeded", "service count exceeds active.max_services", "$.inputs.services", {"service_count": len(services), "max_services": max_services}))

    if active_requested and upstream_driven and not services:
        source_status.append({
            "source": "active_service",
            "status": "skipped",
            "reason": "no_confirmed_open_ports",
            "message": "Service detection skipped because upstream port stage produced no confirmed open ports.",
            "query_count": 0,
            "probe_count": 0,
        })
        return {
            "source": SOURCE,
            "target": {"type": "service", "value": target_value},
            "mode": mode,
            "detection_depth": detection_depth,
            "observations": [],
            "results": [],
            "source_status": source_status[:MAX_ERRORS],
            "summary": {
                "status": "skipped",
                "reason": "no_confirmed_open_ports",
                "service_count": 0,
                "observation_count": 0,
                "result_count": 0,
                "passive_sources": selected_passive_sources(passive_options, mode),
                "active_enabled": active_requested,
                "detection_depth": detection_depth,
                "estimated_api_queries": 0,
                "estimated_service_probes": 0,
                "requires_active_verify": active_requested,
                "requires_high_risk": high_risk_requested,
                "requires_approval": high_risk_requested,
                "source_status_count": len(source_status),
                "error_count": len(errors),
            },
            "errors": errors[:MAX_ERRORS],
            "safety": {
                "target_type_service_only": True,
                "authorization_scope_required": True,
                "active_policy_allowed": bool(policy.get("allow_active_verify")),
                "high_risk_policy_allowed": bool(policy.get("allow_high_risk")),
                "active_service_probes": 0,
                "external_api_queries": 0,
                "shell_commands": 0,
                "exploit_attempts": 0,
                "bruteforce_attempts": 0,
                "dos_attempts": 0,
            },
        }

    if mode in {"fixture", "passive_intel", "hybrid"}:
        observations.extend(run_passive_sources(payload, services, passive_options, mode, source_status, output_options))

    if active_requested and not errors:
        observations.extend(run_active_sources(services, active_options, detection_depth, source_status, output_options))
    elif active_requested:
        source_status.append({"source": "active_service", "status": "skipped_policy_denied", "message": "Active service detection was not executed.", "query_count": 0, "probe_count": 0})

    results = merge_observations(
        observations,
        merge_options,
        include_unknown=bool(output_options.get("include_unknown")),
        services=services,
    )
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    if not bool(output_options.get("include_conflicts")):
        for result in results:
            result["conflict"] = False
            result["conflict_reason"] = None

    return {
        "source": SOURCE,
        "target": {"type": "service", "value": target_value},
        "mode": mode,
        "detection_depth": detection_depth,
        "observations": observations[:MAX_RESULTS],
        "results": results[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "service_count": len(services),
            "observation_count": len(observations),
            "result_count": len(results),
            "passive_sources": selected_passive_sources(passive_options, mode),
            "active_enabled": active_requested,
            "detection_depth": detection_depth,
            "estimated_api_queries": estimated_api_queries(passive_options),
            "estimated_service_probes": len(services) * max_probes if active_requested else 0,
            "requires_active_verify": active_requested,
            "requires_high_risk": high_risk_requested,
            "requires_approval": high_risk_requested,
            "source_status_count": len(source_status),
            "error_count": len(errors),
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "target_type_service_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": bool(policy.get("allow_active_verify")),
            "high_risk_policy_allowed": bool(policy.get("allow_high_risk")),
            "active_service_probes": sum(int(item.get("probe_count", 0)) for item in source_status),
            "external_api_queries": 0,
            "shell_commands": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
            "dos_attempts": 0,
        },
    }


def run_passive_sources(
    payload: dict[str, Any],
    services: list[dict[str, Any]],
    options: dict[str, Any],
    mode: str,
    source_status: list[dict[str, Any]],
    output_options: dict[str, Any],
) -> list[dict[str, Any]]:
    sources = selected_passive_sources(options, mode)
    observations: list[dict[str, Any]] = []
    if "fixture" in sources:
        path = string_or(options.get("fixture_file"), string_or(options.get("local_cache_file"), "examples/fixture.services.example.com.json"))
        observations.extend(load_file_source("fixture", path, services, source_status, output_options))
    if "local_cache" in sources:
        path = string_or(options.get("local_cache_file"), "examples/fixture.services.example.com.json")
        observations.extend(load_file_source("local_cache", path, services, source_status, output_options))
    if "passive_service_cache" in sources:
        path = string_or(options.get("passive_service_cache_file"), string_or(options.get("local_cache_file"), "examples/fixture.services.example.com.json"))
        try:
            records = passive_service_cache.load_passive_services(PLUGIN_ROOT, path)
            observations.extend(normalize_services(records, "passive_service_cache", services, output_options))
            source_status.append({"source": "passive_service_cache", "status": "ok", "message": "Passive service cache loaded.", "query_count": 0, "probe_count": 0})
        except Exception as error:
            source_status.append({"source": "passive_service_cache", "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
    if "upstream_port_result" in sources:
        records = upstream_findings.extract(payload)
        observations.extend(normalize_services(records, "upstream_port_result", services, output_options))
        source_status.append({"source": "upstream_port_result", "status": "ok", "message": "Upstream port findings parsed.", "query_count": 0, "probe_count": 0})
        observations.extend(extract_fofa_shodan(records, services, output_options))
    if "upstream_dns_result" in sources:
        source_status.append({"source": "upstream_dns_result", "status": "ok", "message": "Upstream DNS findings are used as auxiliary host evidence only.", "query_count": 0, "probe_count": 0})
    if "external_fingerprint_intel" in sources:
        records, status = external_fingerprint.query(services, options)
        observations.extend(normalize_services(records, "external_fingerprint_intel", services, output_options))
        status.setdefault("probe_count", 0)
        source_status.append(status)
    return observations


def load_file_source(
    source: str,
    path: str,
    services: list[dict[str, Any]],
    source_status: list[dict[str, Any]],
    output_options: dict[str, Any],
) -> list[dict[str, Any]]:
    try:
        records = local_cache.load_services(PLUGIN_ROOT, path)
        if source != "fixture":
            records = [
                {
                    **record,
                    "source": source,
                    "source_type": SOURCE_TYPES[source],
                    "detection_depth": depth_for_source(source),
                }
                for record in records
            ]
        observations = normalize_services(records, source, services, output_options)
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_active_sources(
    services: list[dict[str, Any]],
    options: dict[str, Any],
    detection_depth: str,
    source_status: list[dict[str, Any]],
    output_options: dict[str, Any],
) -> list[dict[str, Any]]:
    profiles = [profile for profile in list_of_strings(options.get("probe_profiles", []), "$.options.active.probe_profiles") if profile in ACTIVE_PROFILES]
    timeout = bounded_int(options.get("timeout_seconds"), 3, 1, 30)
    concurrency = bounded_int(options.get("concurrency"), 5, 1, 20)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 5, 1, 20)
    max_response_bytes = bounded_int(options.get("max_response_bytes"), 4096, 128, 65536)
    observations: list[dict[str, Any]] = []
    limiter = RateLimiter(rate_limit)
    probe_count = 0

    def probe(service: dict[str, Any]) -> tuple[list[dict[str, Any]], int, str | None]:
        active_records: list[dict[str, Any]] = []
        count = 0
        try:
            if "tcp_banner" in profiles and detection_depth in {"safe", "standard"}:
                count += 1
                record = active_safe.tcp_banner(service, timeout, max_response_bytes)
                if record:
                    active_records.append(record)
            for profile in profiles:
                if profile in {"tls_hello", "http_head", "http_get_root", "standard_probe"}:
                    count += 1
            return normalize_services(active_records, "tcp_banner", services, output_options), count, None
        except Exception as error:
            return [], count, safe_message(error)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for service in services:
            limiter.wait()
            futures.append(pool.submit(probe, service))
        for future in concurrent.futures.as_completed(futures):
            records, count, error = future.result()
            probe_count += count
            observations.extend(records)
            if error:
                source_status.append({"source": "active_service", "status": "error", "message": error, "query_count": 0, "probe_count": count})
    source_status.append({"source": "active_service", "status": "ok", "message": "Active service detection completed.", "query_count": 0, "probe_count": probe_count})
    if detection_depth == "deep":
        source_status.append({"source": "deep_probe", "status": "skipped_not_implemented", "message": "Deep fingerprinting framework is policy-gated and disabled by default.", "query_count": 0, "probe_count": 0})
    if detection_depth == "external_fingerprint":
        source_status.append({"source": "external_fingerprint", "status": "skipped_not_implemented", "message": "External fingerprint tool execution is reserved for a later allowlisted adapter.", "query_count": 0, "probe_count": 0})
    return observations


def normalize_services(
    records: list[dict[str, Any]],
    default_source: str,
    target_services: list[dict[str, Any]],
    output_options: dict[str, Any],
) -> list[dict[str, Any]]:
    target_keys = {(service["address"], service["protocol"], service["port"]) for service in target_services}
    normalized: list[dict[str, Any]] = []
    for record in records:
        address = validate_address(str(record.get("address", "")), "$.service.address")
        port = validate_port(record.get("port"), "$.service.port")
        protocol = str(record.get("protocol") or "tcp").lower()
        if (address, protocol, port) not in target_keys:
            continue
        source = str(record.get("source") or default_source)
        if source not in SOURCE_BASE_CONFIDENCE:
            source = default_source
        service_name = clean_text(record.get("service") or "unknown", 64)
        banner = sanitize_banner(record.get("banner_summary"), output_options)
        http = sanitize_http(record.get("http") if isinstance(record.get("http"), dict) else {}, output_options)
        tls = sanitize_tls(record.get("tls") if isinstance(record.get("tls"), dict) else {})
        normalized.append(
            {
                "address": address,
                "port": port,
                "protocol": protocol,
                "service": service_name,
                "transport": nullable_text(record.get("transport"), 32),
                "product": nullable_text(record.get("product"), 128),
                "version": nullable_text(record.get("version"), 64),
                "hostnames": clean_string_array(record.get("hostnames", []), 16, 253),
                "banner_summary": banner,
                "http": http,
                "tls": tls,
                "source": source,
                "source_type": str(record.get("source_type") or SOURCE_TYPES[source]),
                "detection_depth": str(record.get("detection_depth") or depth_for_source(source)),
                "observed_at": string_or(record.get("observed_at"), now_rfc3339()),
                "source_updated_at": record.get("source_updated_at"),
                "confidence": clamp_float(record.get("confidence", SOURCE_BASE_CONFIDENCE[source])),
                "evidence": record.get("evidence") if isinstance(record.get("evidence"), dict) else {"summary": f"Service on {address}:{port} identified as {service_name} from {source}.", "items": []},
                "source_details": record.get("source_details") if isinstance(record.get("source_details"), list) else [],
            }
        )
    return normalized


def extract_fofa_shodan(records: list[dict[str, Any]], services: list[dict[str, Any]], output_options: dict[str, Any]) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    for record in records:
        for detail in record.get("source_details", []):
            if not isinstance(detail, dict):
                continue
            source = str(detail.get("source", ""))
            if source not in {"fofa_enrichment", "shodan_enrichment"}:
                continue
            item = dict(record)
            item["source"] = source
            item["source_type"] = "passive_intel"
            item["detection_depth"] = "passive"
            item["confidence"] = SOURCE_BASE_CONFIDENCE[source]
            extracted.extend(normalize_services([item], source, services, output_options))
    return extracted


def merge_observations(
    observations: list[dict[str, Any]],
    options: dict[str, Any],
    include_unknown: bool,
    services: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    stale_days = bounded_int(options.get("stale_after_days"), 30, 1, 3650)
    grouped: dict[tuple[str, str, int, str, str | None, str | None], list[dict[str, Any]]] = {}
    values_by_base: dict[tuple[str, str, int], set[tuple[str, str | None, str | None]]] = {}
    for item in observations:
        key = (
            str(item["address"]),
            str(item["protocol"]),
            int(item["port"]),
            str(item["service"]),
            item.get("product"),
            item.get("version"),
        )
        grouped.setdefault(key, []).append(item)
        values_by_base.setdefault((key[0], key[1], key[2]), set()).add((key[3], key[4], key[5]))

    results: list[dict[str, Any]] = []
    for (address, protocol, port, service, product, version), items in sorted(grouped.items()):
        details = [source_detail(item, stale_days) for item in items]
        sources = sorted({str(item["source"]) for item in items})
        source_types = {str(item.get("source_type")) for item in items}
        stale = all(detail["stale"] for detail in details)
        conflict = len(values_by_base.get((address, protocol, port), set())) > 1
        agreement = source_agreement(source_types, sources, stale, conflict)
        conflict_reason = service_conflict_reason(values_by_base.get((address, protocol, port), set()), conflict)
        confidence = calculate_confidence(items, details, agreement, conflict, conflict_reason)
        hostnames = sorted({hostname for item in items for hostname in item.get("hostnames", [])})
        results.append(
            {
                "type": "service_result",
                "address": address,
                "port": port,
                "protocol": protocol,
                "service": service,
                "transport": first_non_null(item.get("transport") for item in items),
                "product": product,
                "version": version,
                "hostnames": hostnames,
                "banner_summary": first_non_null(item.get("banner_summary") for item in items),
                "http": first_non_empty_dict(item.get("http") for item in items),
                "tls": first_non_empty_dict(item.get("tls") for item in items),
                "sources": sources,
                "source_details": details,
                "source_count": len(sources),
                "source_agreement": agreement,
                "conflict": conflict,
                "conflict_reason": conflict_reason,
                "detection_depth": strongest_depth(items),
                "risk_level": risk_for_depth(strongest_depth(items)),
                "observed_at": max(str(item.get("observed_at", "")) for item in items),
                "stale": stale,
                "confidence": confidence,
                "confidence_strategy": "weighted_sources",
                "evidence": {"summary": f"Service on {address}:{port} identified as {service}.", "items": []},
            }
        )
    if include_unknown:
        known = {(item["address"], item["protocol"], item["port"]) for item in results}
        for service in services:
            key = (service["address"], service["protocol"], service["port"])
            if key not in known:
                results.append(unknown_result(service))
    return results


def source_detail(item: dict[str, Any], stale_days: int) -> dict[str, Any]:
    observed_at = str(item.get("observed_at") or "")
    return {
        "source": str(item.get("source")),
        "source_type": str(item.get("source_type")),
        "detection_depth": str(item.get("detection_depth")),
        "observed_at": observed_at,
        "source_updated_at": item.get("source_updated_at"),
        "confidence": clamp_float(item.get("confidence", 0.0)),
        "stale": is_stale(observed_at, stale_days),
        "evidence": item.get("evidence", {"summary": "", "items": []}),
    }


def source_agreement(source_types: set[str], sources: list[str], stale: bool, conflict: bool) -> str:
    if conflict:
        return "conflict"
    if stale and source_types and source_types.issubset({"fixture", "passive_intel"}):
        return "stale_passive"
    if len(sources) > 1:
        return "consistent"
    if "active" in source_types:
        return "active_only"
    if "passive_intel" in source_types or "fixture" in source_types:
        return "passive_only"
    return "unknown"


def service_conflict_reason(values: set[tuple[str, str | None, str | None]] | None, conflict: bool) -> str | None:
    if not conflict or not values:
        return None
    services = {value[0] for value in values}
    products = {(value[1], value[2]) for value in values}
    if len(services) > 1:
        return "service_product_mismatch"
    if len(products) > 1:
        return "product_version_mismatch"
    return "service_product_mismatch"


def calculate_confidence(items: list[dict[str, Any]], details: list[dict[str, Any]], agreement: str, conflict: bool, conflict_reason: str | None) -> float:
    confidence = max(clamp_float(item.get("confidence", 0.0)) for item in items)
    sources = {str(item.get("source")) for item in items}
    source_types = {str(item.get("source_type")) for item in items}
    if len(sources) > 1:
        confidence += 0.05
    if "active" in source_types and ("passive_intel" in source_types or "fixture" in source_types):
        confidence += 0.10
    if any(detail["stale"] for detail in details):
        confidence -= 0.10
    if conflict:
        confidence -= 0.15 if conflict_reason == "service_product_mismatch" else 0.20
    if any(len(str(item.get("banner_summary") or "")) < 8 and item.get("banner_summary") for item in items):
        confidence -= 0.05
    if agreement == "conflict":
        confidence -= 0.05
    return clamp_float(confidence)


def dry_run_output(target_value: str, services: list[dict[str, Any]], options: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    detection_depth = string_at(options, "detection_depth", "$.options.detection_depth")
    active_enabled = bool(active_options.get("enabled"))
    high_risk = detection_depth in {"deep", "external_fingerprint"}
    return {
        "source": SOURCE,
        "target": {"type": "service", "value": target_value},
        "mode": "dry_run",
        "detection_depth": detection_depth,
        "observations": [],
        "results": [],
        "source_status": [{"source": "dry_run", "status": "ok", "message": "No service probe was executed.", "query_count": 0, "probe_count": 0}],
        "summary": {
            "service_count": len(services),
            "observation_count": 0,
            "result_count": 0,
            "passive_sources": selected_passive_sources(passive_options, "passive_intel"),
            "active_enabled": active_enabled,
            "detection_depth": detection_depth,
            "estimated_api_queries": estimated_api_queries(passive_options),
            "estimated_service_probes": len(services) * bounded_int(active_options.get("max_probes_per_service"), 3, 1, 10) if active_enabled else 0,
            "requires_active_verify": active_enabled,
            "requires_high_risk": high_risk,
            "requires_approval": high_risk,
            "source_status_count": 1,
            "error_count": 0,
        },
        "errors": [],
        "safety": {
            "target_type_service_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": bool(policy.get("allow_active_verify")),
            "high_risk_policy_allowed": bool(policy.get("allow_high_risk")),
            "active_service_probes": 0,
            "external_api_queries": 0,
            "shell_commands": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
            "dos_attempts": 0,
        },
    }


def selected_passive_sources(options: dict[str, Any], mode: str) -> list[str]:
    if mode == "fixture":
        return ["fixture"]
    if not bool(options.get("enabled")):
        return []
    sources = list_of_strings(options.get("sources", ["upstream_port_result", "local_cache", "fixture"]), "$.options.passive_intel.sources")
    return [source for source in sources if source in PASSIVE_SOURCES]


def estimated_api_queries(options: dict[str, Any]) -> int:
    sources = set(list_of_strings(options.get("sources", []), "$.options.passive_intel.sources"))
    return bounded_int(options.get("max_queries"), 0, 0, 10000) if "external_fingerprint_intel" in sources else 0


def unknown_result(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "service_result",
        "address": service["address"],
        "port": service["port"],
        "protocol": service["protocol"],
        "service": "unknown",
        "transport": None,
        "product": None,
        "version": None,
        "hostnames": service.get("hostnames", []),
        "banner_summary": None,
        "http": {},
        "tls": {},
        "sources": [],
        "source_details": [],
        "source_count": 0,
        "source_agreement": "unknown",
        "conflict": False,
        "conflict_reason": None,
        "detection_depth": "passive",
        "risk_level": "low",
        "observed_at": None,
        "stale": False,
        "confidence": 0.0,
        "confidence_strategy": "weighted_sources",
        "evidence": {"summary": f"No service identity was observed for {service['address']}:{service['port']}.", "items": []},
    }


def validate_services(raw_services: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_services, list):
        raise InputError("inputs.services must be an array", "$.inputs.services")
    services = []
    for index, raw in enumerate(raw_services):
        if not isinstance(raw, dict):
            raise InputError("service item must be an object", f"$.inputs.services[{index}]")
        address = validate_address(str(raw.get("address", "")), f"$.inputs.services[{index}].address")
        port = validate_port(raw.get("port"), f"$.inputs.services[{index}].port")
        protocol = str(raw.get("protocol") or "tcp").lower()
        if protocol not in {"tcp", "udp"}:
            raise InputError("protocol must be tcp or udp", f"$.inputs.services[{index}].protocol")
        services.append({"address": address, "port": port, "protocol": protocol, "hostnames": clean_string_array(raw.get("hostnames", []), 16, 253)})
    return services


def merge_services(primary: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, int, str], dict[str, Any]] = {}
    for service in primary + extra:
        key = (str(service["address"]), int(service["port"]), str(service.get("protocol", "tcp")))
        current = merged.get(key)
        if current is None:
            merged[key] = service
            continue
        hostnames = sorted(set(current.get("hostnames", [])) | set(service.get("hostnames", [])))
        current["hostnames"] = hostnames[:16]
    return [merged[key] for key in sorted(merged)]


def service_from_target(value: str) -> dict[str, Any] | None:
    if ":" not in value:
        return None
    address, port_text = value.rsplit(":", 1)
    try:
        port = validate_port(int(port_text), "$.target.value")
        return {"address": validate_address(address, "$.target.value"), "port": port, "protocol": "tcp", "hostnames": []}
    except (InputError, ValueError):
        return None


def validate_address(value: str, field: str) -> str:
    address = value.strip().lower()
    if not address:
        raise InputError("address is required", field)
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        if HOST_RE.match(address):
            return address
    raise InputError("address must be an IP address or hostname", field)


def validate_port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError("port must be an integer", field)
    if value < 1 or value > 65535:
        raise InputError("port must be between 1 and 65535", field)
    return value


def depth_for_source(source: str) -> str:
    if source in {"tcp_banner", "tls_hello", "http_head", "http_get_root"}:
        return "safe"
    if source == "standard_probe":
        return "standard"
    if source == "deep_probe":
        return "deep"
    if source == "external_fingerprint":
        return "external_fingerprint"
    if source == "fixture":
        return "fixture"
    return "passive"


def strongest_depth(items: list[dict[str, Any]]) -> str:
    order = ["fixture", "passive", "safe", "standard", "deep", "external_fingerprint"]
    best = "passive"
    for item in items:
        depth = str(item.get("detection_depth") or "passive")
        if depth in order and order.index(depth) > order.index(best):
            best = depth
    return best


def risk_for_depth(depth: str) -> str:
    if depth in {"deep", "external_fingerprint"}:
        return "high"
    if depth in {"safe", "standard"}:
        return "medium"
    return "low"


def sanitize_banner(value: Any, options: dict[str, Any]) -> str | None:
    limit = bounded_int(options.get("truncate_banner_bytes"), 512, 64, 4096)
    text = nullable_text(value, limit)
    if text is None:
        return None
    if bool(options.get("mask_sensitive_headers")):
        text = SENSITIVE_HEADER_RE.sub(lambda match: f"{match.group(1)}: [redacted]", text)
    return text[:limit]


def sanitize_http(value: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if isinstance(value.get("status"), int):
        sanitized["status"] = value["status"]
    for field in ["server", "title"]:
        if field in value:
            sanitized[field] = sanitize_banner(value.get(field), options)
    if isinstance(value.get("headers"), dict):
        headers = {}
        for key, header_value in value["headers"].items():
            key_text = clean_text(key, 64)
            if key_text.lower() in {"authorization", "cookie", "set-cookie", "x-api-key"}:
                headers[key_text] = "[redacted]"
            else:
                headers[key_text] = clean_text(header_value, 128)
        sanitized["headers"] = headers
    return sanitized


def sanitize_tls(value: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in ["subject", "issuer", "not_before", "not_after"]:
        if field in value:
            sanitized[field] = nullable_text(value.get(field), 256)
    if isinstance(value.get("san_count"), int):
        sanitized["san_count"] = max(0, min(value["san_count"], 10000))
    return sanitized


def clean_string_array(value: Any, max_items: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value[:max_items]:
        if isinstance(item, str):
            items.append(clean_text(item, max_length))
    return items


def clean_text(value: Any, max_length: int) -> str:
    text = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return text[:max_length]


def nullable_text(value: Any, max_length: int) -> str | None:
    if value is None:
        return None
    text = clean_text(value, max_length)
    return text or None


def object_at(payload: dict[str, Any], field: str, path: str) -> dict[str, Any]:
    value = payload.get(field)
    if not isinstance(value, dict):
        raise InputError(f"{field} must be an object", path)
    return value


def string_at(payload: dict[str, Any], field: str, path: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise InputError(f"{field} must be a string", path)
    return value


def list_of_strings(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise InputError("field must be an array of strings", path)
    return list(value)


def string_or(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return min(max(value, minimum), maximum)
    return default


def clamp_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return min(max(number, 0.0), 1.0)


def first_non_null(values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def first_non_empty_dict(values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, dict) and value:
            return value
    return {}


def is_stale(observed_at: str, stale_days: int) -> bool:
    try:
        parsed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    now = dt.datetime.now(dt.timezone.utc)
    return now - parsed.astimezone(dt.timezone.utc) > dt.timedelta(days=stale_days)


def now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_message(error: BaseException) -> str:
    return str(error).replace("\x00", "").replace("\n", " ")[:512]


def standard_error(code: str, message: str, field: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"code": code, "message": message, "field": field, "details": details}


if __name__ == "__main__":
    raise SystemExit(main())
