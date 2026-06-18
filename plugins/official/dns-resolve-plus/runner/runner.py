#!/usr/bin/env python3
"""Passive-intel-first DNS resolution runner for SentinelFlow."""

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

from sources import external_dns_intel, local_cache, passive_dns_cache, resolver_client


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "dns-resolve-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
DOMAIN_RE = re.compile(
    r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
PASSIVE_SOURCES = {"fixture", "local_cache", "passive_dns_cache", "external_dns_intel"}
ACTIVE_SOURCES = {"system_resolver", "public_resolver", "authoritative_trace"}
SOURCE_BASE_CONFIDENCE = {
    "fixture": 0.70,
    "local_cache": 0.70,
    "passive_dns_cache": 0.75,
    "external_dns_intel": 0.80,
    "system_resolver": 0.85,
    "public_resolver": 0.85,
    "authoritative_trace": 0.90,
}
SOURCE_TYPES = {
    "fixture": "fixture",
    "local_cache": "passive_intel",
    "passive_dns_cache": "passive_intel",
    "external_dns_intel": "passive_intel",
    "system_resolver": "active",
    "public_resolver": "active",
    "authoritative_trace": "active",
}


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
    if target.get("type") != "domain":
        raise InputError("target.type must be domain", "$.target.type")
    root_domain = validate_domain(string_at(target, "value", "$.target.value"), "$.target.value")
    inputs = object_at(payload, "inputs", "$.inputs")
    domains = validate_domains(inputs.get("domains", [root_domain]), root_domain)
    domains = merge_domains(domains, domains_from_findings(inputs.get("findings", []), root_domain))

    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "active", "hybrid"}:
        raise InputError("unsupported DNS mode", "$.options.mode")
    record_types = list_of_strings(options.get("record_types", ["A", "AAAA", "CNAME"]), "$.options.record_types")
    if not record_types or any(record_type not in RECORD_TYPES for record_type in record_types):
        raise InputError("record_types contains an unsupported DNS type", "$.options.record_types")

    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    merge_options = object_at(options, "merge", "$.options.merge")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")

    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    active_enabled = bool(active_options.get("enabled"))
    active_requested = mode == "active" or (mode == "hybrid" and active_enabled)
    authoritative_trace = bool(active_options.get("authoritative_trace"))
    risk_acknowledged = bool(options.get("risk_acknowledged"))

    if mode == "dry_run":
        return dry_run_output(root_domain, domains, record_types, options, policy)

    max_domains = bounded_int(active_options.get("max_domains"), 100, 1, 1000)
    max_queries = bounded_int(active_options.get("max_queries"), 500, 1, 5000)
    estimated_queries = len(domains) * len(record_types)
    if len(domains) > max_domains:
        errors.append(standard_error("InputLimitExceeded", "domain count exceeds active.max_domains", "$.inputs.domains", {"domain_count": len(domains), "max_domains": max_domains}))
    if estimated_queries > max_queries:
        errors.append(standard_error("InputLimitExceeded", "estimated DNS queries exceed active.max_queries", "$.options.active.max_queries", {"estimated_dns_queries": estimated_queries, "max_queries": max_queries}))
    if active_requested and not bool(policy.get("allow_active_verify")):
        errors.append(standard_error("PolicyDenied", "active DNS resolution requires policy.allow_active_verify=true", "$.policy.allow_active_verify", {"mode": mode, "activeEnabled": active_enabled}))
    if active_requested and authoritative_trace and not risk_acknowledged:
        errors.append(standard_error("PolicyDenied", "authoritative_trace requires options.risk_acknowledged=true", "$.options.risk_acknowledged", {"authoritative_trace": True}))

    if mode in {"fixture", "passive_intel", "hybrid"}:
        observations.extend(run_passive_sources(root_domain, domains, record_types, passive_options, mode, source_status))

    if active_requested and not errors:
        observations.extend(run_active_sources(domains, record_types, active_options, source_status))
    elif active_requested:
        source_status.append({"source": "active_dns", "status": "skipped_policy_denied", "message": "Active DNS was not executed.", "query_count": 0})

    results = merge_observations(
        observations,
        domains,
        record_types,
        merge_options,
        include_unresolved=bool(output_options.get("include_unresolved")),
    )
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    if not bool(output_options.get("include_conflicts")):
        for result in results:
            result["conflict"] = False
            result["conflict_reason"] = None
    invalid_special_count = sum(
        1 for result in results if result.get("status") == "invalid_special_address"
    )
    public_routable_count = sum(1 for result in results if result.get("public_routable"))
    valid_for_port_probe_count = sum(
        1 for result in results if result.get("valid_for_port_probe")
    )

    return {
        "source": SOURCE,
        "target": {"type": "domain", "value": root_domain},
        "mode": mode,
        "record_types": record_types,
        "observations": observations[:MAX_RESULTS],
        "results": results[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "domain_count": len(domains),
            "record_types": record_types,
            "observation_count": len(observations),
            "result_count": len(results),
            "invalid_special_address_count": invalid_special_count,
            "public_routable_result_count": public_routable_count,
            "valid_for_port_probe_count": valid_for_port_probe_count,
            "passive_sources": selected_passive_sources(passive_options, mode),
            "active_enabled": active_requested,
            "estimated_api_queries": estimated_api_queries(passive_options),
            "estimated_dns_queries": estimated_queries if active_requested else 0,
            "requires_active_verify": active_requested,
            "requires_high_risk": False,
            "requires_approval": False,
            "source_status_count": len(source_status),
            "error_count": len(errors),
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "target_type_domain_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": bool(policy.get("allow_active_verify")),
            "high_risk_policy_allowed": bool(policy.get("allow_high_risk")),
            "active_dns_queries": sum(int(item.get("query_count", 0)) for item in source_status if item.get("source") in ACTIVE_SOURCES or item.get("source") == "active_dns"),
            "external_api_queries": 0,
            "shell_commands": 0,
            "exploit_attempts": 0,
        },
    }


def run_passive_sources(
    root_domain: str,
    domains: list[str],
    record_types: list[str],
    options: dict[str, Any],
    mode: str,
    source_status: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sources = selected_passive_sources(options, mode)
    observations: list[dict[str, Any]] = []
    if "fixture" in sources:
        path = string_or(options.get("fixture_file"), string_or(options.get("local_cache_file"), "examples/fixture.dns.example.com.json"))
        observations.extend(load_file_source("fixture", path, root_domain, domains, record_types, source_status))
    if "local_cache" in sources:
        path = string_or(options.get("local_cache_file"), "examples/fixture.dns.example.com.json")
        observations.extend(load_file_source("local_cache", path, root_domain, domains, record_types, source_status))
    if "passive_dns_cache" in sources:
        path = string_or(options.get("passive_dns_cache_file"), string_or(options.get("local_cache_file"), "examples/fixture.dns.example.com.json"))
        try:
            records = passive_dns_cache.load_passive_records(PLUGIN_ROOT, path)
            observations.extend(normalize_records(records, "passive_dns_cache", root_domain, domains, record_types))
            source_status.append({"source": "passive_dns_cache", "status": "ok", "message": "Passive DNS cache loaded.", "query_count": 0})
        except Exception as error:
            source_status.append({"source": "passive_dns_cache", "status": "error", "message": safe_message(error), "query_count": 0})
    if "external_dns_intel" in sources:
        records, status = external_dns_intel.query(domains, record_types, options)
        observations.extend(normalize_records(records, "external_dns_intel", root_domain, domains, record_types))
        source_status.append(status)
    return observations


def load_file_source(
    source: str,
    path: str,
    root_domain: str,
    domains: list[str],
    record_types: list[str],
    source_status: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        records = local_cache.load_records(PLUGIN_ROOT, path)
        if source != "fixture":
            records = [
                {**record, "source": source, "source_type": SOURCE_TYPES[source]}
                for record in records
            ]
        observations = normalize_records(records, source, root_domain, domains, record_types)
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0})
        return []


def run_active_sources(
    domains: list[str],
    record_types: list[str],
    options: dict[str, Any],
    source_status: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resolver_mode = string_or(options.get("resolver_mode"), "public_resolver")
    if resolver_mode not in {"system_resolver", "public_resolver"}:
        source_status.append({"source": resolver_mode, "status": "error", "message": "unsupported resolver_mode", "query_count": 0})
        return []
    timeout = bounded_int(options.get("timeout_seconds"), 3, 1, 30)
    concurrency = bounded_int(options.get("concurrency"), 5, 1, 20)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 5, 1, 20)
    resolvers = list_of_strings(options.get("resolvers", ["1.1.1.1", "8.8.8.8"]), "$.options.active.resolvers")
    resolver_client.validate_resolvers(resolvers)
    limiter = RateLimiter(rate_limit)
    observations: list[dict[str, Any]] = []
    query_count = 0

    def resolve(domain: str) -> tuple[list[dict[str, Any]], int, str | None]:
        try:
            if resolver_mode == "system_resolver":
                records, count = resolver_client.resolve_system(domain, record_types, timeout)
            else:
                records, count = resolver_client.resolve_public(domain, record_types, resolvers, timeout)
            normalized = []
            for record in records:
                item = {
                    "domain": domain,
                    "record_type": record.get("record_type"),
                    "value": record.get("value"),
                    "ttl": record.get("ttl"),
                    "source": resolver_mode,
                    "source_type": "active",
                    "observed_at": now_rfc3339(),
                    "source_updated_at": None,
                    "confidence": SOURCE_BASE_CONFIDENCE[resolver_mode],
                    "evidence": {"summary": f"{record.get('record_type')} record for {domain} observed by {resolver_mode}.", "items": []},
                }
                normalized.append(item)
            return normalized, count, None
        except Exception as error:
            return [], 0, safe_message(error)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for domain in domains:
            limiter.wait()
            futures.append(pool.submit(resolve, domain))
        for future in concurrent.futures.as_completed(futures):
            records, count, error = future.result()
            query_count += count
            observations.extend(records)
            if error:
                source_status.append({"source": resolver_mode, "status": "error", "message": error, "query_count": 0})
    source_status.append({"source": resolver_mode, "status": "ok", "message": "Active DNS resolver completed.", "query_count": query_count})
    if bool(options.get("authoritative_trace")):
        source_status.append({"source": "authoritative_trace", "status": "skipped_not_implemented", "message": "Authoritative trace is policy-gated and reserved for a later provider implementation.", "query_count": 0})
    return observations


def normalize_records(
    records: list[dict[str, Any]],
    default_source: str,
    root_domain: str,
    domains: list[str],
    record_types: list[str],
) -> list[dict[str, Any]]:
    domain_set = set(domains)
    normalized: list[dict[str, Any]] = []
    for record in records:
        domain = validate_domain(str(record.get("domain", "")), "$.record.domain")
        if domain not in domain_set or not domain.endswith(root_domain):
            continue
        record_type = str(record.get("record_type", ""))
        if record_type not in record_types:
            continue
        value = str(record.get("value", "")).strip()
        if not value:
            continue
        source = str(record.get("source") or default_source)
        if source not in SOURCE_BASE_CONFIDENCE:
            source = default_source
        confidence = record.get("confidence", SOURCE_BASE_CONFIDENCE[source])
        observed_at = string_or(record.get("observed_at"), now_rfc3339())
        normalized.append(
            {
                "domain": domain,
                "record_type": record_type,
                "value": value,
                "ttl": record.get("ttl"),
                "source": source,
                "source_type": str(record.get("source_type") or SOURCE_TYPES[source]),
                "observed_at": observed_at,
                "source_updated_at": record.get("source_updated_at"),
                "confidence": clamp_float(confidence),
                "evidence": record.get("evidence") if isinstance(record.get("evidence"), dict) else {"summary": f"{record_type} record for {domain} observed from {source}.", "items": []},
            }
        )
    return normalized


def domains_from_findings(raw_findings: Any, root_domain: str) -> list[str]:
    if not isinstance(raw_findings, list):
        return []
    domains: list[str] = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            data = evidence.get("data")
            if not isinstance(data, dict):
                continue
            value = data.get("x-sentinelflow-subdomain.subdomain") or data.get("x-sentinelflow-dns.domain")
            if not isinstance(value, str):
                continue
            try:
                domain = validate_domain(value, "$.inputs.findings.evidence.data")
            except InputError:
                continue
            if domain.endswith(root_domain):
                domains.append(domain)
    return domains


def merge_domains(primary: list[str], extra: list[str]) -> list[str]:
    merged: dict[str, None] = {}
    for domain in primary + extra:
        merged.setdefault(domain, None)
    return sorted(merged)


def merge_observations(
    observations: list[dict[str, Any]],
    domains: list[str],
    record_types: list[str],
    options: dict[str, Any],
    include_unresolved: bool,
) -> list[dict[str, Any]]:
    stale_days = bounded_int(options.get("stale_after_days"), 30, 1, 3650)
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for observation in observations:
        key = (str(observation["domain"]), str(observation["record_type"]), str(observation["value"]))
        grouped.setdefault(key, []).append(observation)
    values_by_rr: dict[tuple[str, str], set[str]] = {}
    source_types_by_rr: dict[tuple[str, str], set[str]] = {}
    for (domain, record_type, value), items in grouped.items():
        values_by_rr.setdefault((domain, record_type), set()).add(value)
        source_types_by_rr.setdefault((domain, record_type), set()).update(str(item.get("source_type")) for item in items)

    results: list[dict[str, Any]] = []
    for (domain, record_type, value), items in sorted(grouped.items()):
        address_class = classify_dns_value(record_type, value)
        public_routable = is_public_routable_class(address_class)
        valid_for_port_probe = record_type in {"A", "AAAA"} and public_routable
        result_status = (
            "resolved"
            if record_type not in {"A", "AAAA"} or public_routable
            else "invalid_special_address"
        )
        details = [source_detail(item, stale_days) for item in items]
        sources = sorted({str(item["source"]) for item in items})
        source_types = source_types_by_rr.get((domain, record_type), set())
        stale = all(detail["stale"] for detail in details)
        conflict = len(values_by_rr.get((domain, record_type), set())) > 1
        agreement = source_agreement(source_types, sources, stale, conflict)
        confidence = 0.0 if result_status == "invalid_special_address" else calculate_confidence(items, details, agreement, conflict)
        summary = (
            f"{record_type} record for {domain} resolved to {value}, but the address is {address_class} and is not valid for public port probing."
            if result_status == "invalid_special_address"
            else f"{record_type} record for {domain} resolved to {value} from {len(sources)} source(s)."
        )
        results.append(
            {
                "type": "dns_result",
                "domain": domain,
                "record_type": record_type,
                "value": value,
                "ttl": first_non_null(item.get("ttl") for item in items),
                "resolved": True,
                "status": result_status,
                "address_class": address_class,
                "public_routable": public_routable,
                "valid_for_port_probe": valid_for_port_probe,
                "sources": sources,
                "source_details": details,
                "source_count": len(sources),
                "source_agreement": agreement,
                "conflict": conflict,
                "conflict_reason": "dns_value_mismatch" if conflict else None,
                "observed_at": max(str(item.get("observed_at", "")) for item in items),
                "stale": stale,
                "confidence": confidence,
                "confidence_strategy": "weighted_sources",
                "risk_level": "low",
                "evidence": {"summary": summary, "items": []},
            }
        )
    if include_unresolved:
        resolved_keys = {(result["domain"], result["record_type"]) for result in results}
        for domain in domains:
            for record_type in record_types:
                if (domain, record_type) not in resolved_keys:
                    results.append(unresolved_result(domain, record_type))
    return results


def source_agreement(source_types: set[str], sources: list[str], stale: bool, conflict: bool) -> str:
    if conflict:
        return "conflict"
    if stale and source_types and source_types.issubset({"fixture", "passive_intel"}):
        return "stale_passive"
    if len(sources) > 1:
        return "consistent"
    if "active" in source_types and ("passive_intel" in source_types or "fixture" in source_types):
        return "consistent"
    if "active" in source_types:
        return "active_only"
    if "passive_intel" in source_types or "fixture" in source_types:
        return "passive_only"
    return "unknown"


def calculate_confidence(items: list[dict[str, Any]], details: list[dict[str, Any]], agreement: str, conflict: bool) -> float:
    confidence = max(clamp_float(item.get("confidence", 0.0)) for item in items)
    sources = {str(item.get("source")) for item in items}
    source_types = {str(item.get("source_type")) for item in items}
    if len(sources) > 1:
        confidence += 0.05
    if "active" in source_types and ("passive_intel" in source_types or "fixture" in source_types):
        confidence += 0.10
    if any(detail["stale"] for detail in details):
        confidence -= 0.10
    if conflict or agreement == "conflict":
        confidence -= 0.20
    return clamp_float(confidence)


def source_detail(item: dict[str, Any], stale_days: int) -> dict[str, Any]:
    observed_at = str(item.get("observed_at") or "")
    return {
        "source": str(item.get("source")),
        "source_type": str(item.get("source_type")),
        "observed_at": observed_at,
        "source_updated_at": item.get("source_updated_at"),
        "confidence": clamp_float(item.get("confidence", 0.0)),
        "stale": is_stale(observed_at, stale_days),
        "evidence": item.get("evidence", {"summary": "", "items": []}),
    }


def unresolved_result(domain: str, record_type: str) -> dict[str, Any]:
    return {
        "type": "dns_result",
        "domain": domain,
        "record_type": record_type,
        "value": None,
        "ttl": None,
        "resolved": False,
        "status": "unresolved",
        "address_class": "not_applicable",
        "public_routable": False,
        "valid_for_port_probe": False,
        "sources": [],
        "source_details": [],
        "source_count": 0,
        "source_agreement": "unresolved",
        "conflict": False,
        "conflict_reason": None,
        "observed_at": None,
        "stale": False,
        "confidence": 0.0,
        "confidence_strategy": "weighted_sources",
        "risk_level": "low",
        "evidence": {"summary": f"No {record_type} record was observed for {domain}.", "items": []},
    }


def classify_dns_value(record_type: str, value: str) -> str:
    if record_type not in {"A", "AAAA"}:
        return "not_applicable"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        mapped_class = classify_dns_value("A", str(address.ipv4_mapped))
        return "ipv4_mapped_public" if mapped_class == "public" else f"ipv4_mapped_{mapped_class}"
    if isinstance(address, ipaddress.IPv4Address):
        if address in ipaddress.ip_network("198.18.0.0/15"):
            return "benchmark"
        if any(
            address in network
            for network in (
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24"),
            )
        ):
            return "documentation"
        if address in ipaddress.ip_network("100.64.0.0/10"):
            return "shared_address_space"
        if address.is_private:
            return "private"
        if address.is_loopback:
            return "loopback"
        if address.is_link_local:
            return "link_local"
        if address.is_multicast:
            return "multicast"
        if address.is_reserved:
            return "reserved"
        if address.is_unspecified:
            return "unspecified"
        if address.is_global:
            return "public"
        return "reserved"
    if address.is_private:
        return "unique_local_ipv6"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_unspecified:
        return "unspecified"
    if address.is_global:
        return "public"
    return "reserved"


def is_public_routable_class(address_class: str) -> bool:
    return address_class in {"public", "ipv4_mapped_public"}


def dry_run_output(root_domain: str, domains: list[str], record_types: list[str], options: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    active_enabled = bool(active_options.get("enabled"))
    authoritative_trace = bool(active_options.get("authoritative_trace"))
    return {
        "source": SOURCE,
        "target": {"type": "domain", "value": root_domain},
        "mode": "dry_run",
        "record_types": record_types,
        "observations": [],
        "results": [],
        "source_status": [{"source": "dry_run", "status": "ok", "message": "No DNS query was executed.", "query_count": 0}],
        "summary": {
            "domain_count": len(domains),
            "record_types": record_types,
            "observation_count": 0,
            "result_count": 0,
            "passive_sources": selected_passive_sources(passive_options, "passive_intel"),
            "active_enabled": active_enabled,
            "estimated_api_queries": estimated_api_queries(passive_options),
            "estimated_dns_queries": len(domains) * len(record_types) if active_enabled else 0,
            "requires_active_verify": active_enabled,
            "requires_high_risk": False,
            "requires_approval": False,
            "source_status_count": 1,
            "error_count": 0,
        },
        "errors": [],
        "safety": {
            "target_type_domain_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": bool(policy.get("allow_active_verify")),
            "high_risk_policy_allowed": bool(policy.get("allow_high_risk")),
            "active_dns_queries": 0,
            "external_api_queries": 0,
            "shell_commands": 0,
            "exploit_attempts": 0,
            "authoritative_trace_requested": authoritative_trace,
        },
    }


def selected_passive_sources(options: dict[str, Any], mode: str) -> list[str]:
    if mode == "fixture":
        return ["fixture"]
    if not bool(options.get("enabled")):
        return []
    sources = list_of_strings(options.get("sources", ["local_cache", "passive_dns_cache", "fixture"]), "$.options.passive_intel.sources")
    return [source for source in sources if source in PASSIVE_SOURCES]


def estimated_api_queries(options: dict[str, Any]) -> int:
    sources = set(list_of_strings(options.get("sources", []), "$.options.passive_intel.sources"))
    return bounded_int(options.get("max_queries"), 0, 0, 10000) if "external_dns_intel" in sources else 0


def validate_domains(raw_domains: Any, root_domain: str) -> list[str]:
    domains = list_of_strings(raw_domains, "$.inputs.domains")
    if not domains:
        return []
    validated = []
    for index, domain in enumerate(domains):
        value = validate_domain(domain, f"$.inputs.domains[{index}]")
        if value != root_domain and not value.endswith(f".{root_domain}"):
            raise InputError("domain is outside the target boundary", f"$.inputs.domains[{index}]")
        validated.append(value)
    return sorted(set(validated))


def validate_domain(value: str, field: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise InputError("invalid domain name", field)
    return domain


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


def is_stale(observed_at: str, stale_days: int) -> bool:
    try:
        parsed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    now = dt.datetime.now(dt.timezone.utc)
    return now - parsed.astimezone(dt.timezone.utc) > dt.timedelta(days=stale_days)


def now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def first_non_null(values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def safe_message(error: BaseException) -> str:
    return str(error).replace("\x00", "").replace("\n", " ")[:512]


def standard_error(code: str, message: str, field: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"code": code, "message": message, "field": field, "details": details}


if __name__ == "__main__":
    raise SystemExit(main())
