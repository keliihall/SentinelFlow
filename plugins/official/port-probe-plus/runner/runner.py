#!/usr/bin/env python3
"""Passive-intel-first bounded TCP connect port verification for SentinelFlow."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "port-probe-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
PASSIVE_SOURCES = {"fixture", "local_cache", "fofa", "shodan"}
PORT_PROFILES = {
    "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
    "minimal": [80, 443],
}
SOURCE_BASE_CONFIDENCE = {
    "fixture": 0.70,
    "local_cache": 0.70,
    "fofa": 0.80,
    "shodan": 0.85,
    "tcp_connect": 0.90,
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
    authorization_scope = string_at(context, "authorization_scope", "$.context.authorization_scope")
    target = object_at(payload, "target", "$.target")
    if target.get("type") != "domain":
        raise InputError("target.type must be domain", "$.target.type")
    root_domain = string_at(target, "value", "$.target.value").strip().lower().rstrip(".")

    inputs = object_at(payload, "inputs", "$.inputs")
    addresses = merge_targets(
        validate_targets(inputs.get("addresses", [])),
        targets_from_findings(inputs.get("findings", [])),
    )
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "active_tcp_connect", "hybrid"}:
        raise InputError("unsupported port probe mode", "$.options.mode")
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    merge_options = object_at(options, "merge", "$.options.merge")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")

    ports = selected_ports(active_options)
    active_requested = mode == "active_tcp_connect" or (mode == "hybrid" and bool(active_options.get("enabled")))
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    lab_profile = active_options.get("execution_profile") == "lab" or options.get("execution_profile") == "lab"
    if mode != "fixture" and not lab_profile:
        addresses = [target for target in addresses if is_public_routable_ip(target["address"])]

    max_targets = bounded_int(active_options.get("max_targets"), 100, 1, 1000)
    max_ports = bounded_int(active_options.get("max_ports"), 20, 1, 100)
    if len(addresses) > max_targets:
        errors.append(standard_error("InputLimitExceeded", "target count exceeds active.max_targets", "$.inputs.addresses", {"target_count": len(addresses), "max_targets": max_targets}))
        addresses = addresses[:max_targets]
    if len(ports) > max_ports:
        errors.append(standard_error("InputLimitExceeded", "port count exceeds active.max_ports", "$.options.active.max_ports", {"port_count": len(ports), "max_ports": max_ports}))
        ports = ports[:max_ports]
    if active_requested and not bool(policy.get("allow_active_verify")):
        errors.append(standard_error("PolicyDenied", "tcp_connect port verification requires policy.allow_active_verify=true", "$.policy.allow_active_verify", {"mode": mode, "activeEnabled": True}))
    if active_options.get("probe_engine") not in {"tcp_connect", None}:
        errors.append(standard_error("PolicyDenied", "only tcp_connect probe_engine is allowed", "$.options.active.probe_engine", {"probe_engine": active_options.get("probe_engine")}))

    if mode == "dry_run":
        return build_output(root_domain, mode, authorization_scope, [], source_status, errors, addresses, ports, active_requested, 0)

    if active_requested and not addresses and mode != "fixture":
        source_status.append({
            "source": "tcp_connect",
            "status": "skipped",
            "reason": "no_public_routable_targets",
            "message": "Port probing skipped because upstream DNS produced no public routable targets.",
            "query_count": 0,
            "probe_count": 0,
        })
        return build_output(
            root_domain,
            mode,
            authorization_scope,
            [],
            source_status,
            errors,
            addresses,
            ports,
            active_requested,
            0,
            status="skipped",
            reason="no_public_routable_targets",
        )

    if mode in {"fixture", "passive_intel", "hybrid"}:
        observations.extend(run_passive_sources(passive_options, addresses, ports, source_status))
    if active_requested and not errors:
        observations.extend(run_tcp_connect(addresses, ports, active_options, source_status))
    elif active_requested:
        source_status.append({"source": "tcp_connect", "status": "skipped_policy_denied", "message": "TCP connect verification was not executed.", "probe_count": 0})

    results = merge_observations(observations, merge_options, include_closed=bool(output_options.get("include_closed")))
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    if not bool(output_options.get("include_conflicts")):
        for result in results:
            result["conflict"] = False
            result["conflict_reason"] = None
    return build_output(root_domain, mode, authorization_scope, results[:MAX_RESULTS], source_status, errors, addresses, ports, active_requested, sum(int(item.get("probe_count", 0)) for item in source_status))


def run_passive_sources(options: dict[str, Any], addresses: list[dict[str, Any]], ports: list[int], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources = list_of_strings(options.get("sources", []))
    observations: list[dict[str, Any]] = []
    if "fixture" in sources:
        path = string_or(options.get("fixture_file"), "examples/fixture.ports.example.com.json")
        observations.extend(load_file_source("fixture", path, addresses, ports, source_status))
    if "local_cache" in sources:
        path = string_or(options.get("local_cache_file"), "examples/fixture.ports.example.com.json")
        observations.extend(load_file_source("local_cache", path, addresses, ports, source_status))
    if "fofa" in sources:
        status = "skipped_missing_secret" if not os.environ.get("FOFA_API_KEY") else "skipped_not_implemented"
        source_status.append({"source": "fofa", "status": status, "message": "FOFA enrichment requires configured secret/provider.", "query_count": 0, "probe_count": 0})
    if "shodan" in sources:
        status = "skipped_missing_secret" if not os.environ.get("SHODAN_API_KEY") else "skipped_not_implemented"
        source_status.append({"source": "shodan", "status": status, "message": "Shodan enrichment requires configured secret/provider.", "query_count": 0, "probe_count": 0})
    return observations


def load_file_source(source: str, path: str, addresses: list[dict[str, Any]], ports: list[int], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        allowed_addresses = {item["address"] for item in addresses}
        observations = []
        for item in data.get("ports", []):
            if not isinstance(item, dict):
                continue
            address = str(item.get("address", "")).strip()
            port = item.get("port")
            if address not in allowed_addresses or port not in ports:
                continue
            observations.append(observation(address, int(port), "tcp", str(item.get("state", "open")), source, item.get("confidence", SOURCE_BASE_CONFIDENCE[source]), item.get("hostnames", []), item))
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_tcp_connect(addresses: list[dict[str, Any]], ports: list[int], options: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeout = bounded_float(options.get("timeout_seconds"), 2.0, 0.2, 10.0)
    concurrency = bounded_int(options.get("concurrency"), 10, 1, 20)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 10, 1, 20)
    limiter = RateLimiter(rate_limit)
    observations: list[dict[str, Any]] = []
    probe_count = 0

    def probe(target: dict[str, Any], port: int) -> dict[str, Any] | None:
        nonlocal probe_count
        probe_count += 1
        address = target["address"]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                code = sock.connect_ex((address, port))
            except OSError:
                return None
        if code == 0:
            return observation(address, port, "tcp", "open", "tcp_connect", SOURCE_BASE_CONFIDENCE["tcp_connect"], target.get("hostnames", []), {"connect_ex": code})
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for target in addresses:
            for port in ports:
                limiter.wait()
                futures.append(pool.submit(probe, target, port))
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                observations.append(item)
    source_status.append({"source": "tcp_connect", "status": "ok", "message": "TCP connect verification completed.", "probe_count": probe_count, "query_count": 0})
    return observations


def merge_observations(observations: list[dict[str, Any]], options: dict[str, Any], include_closed: bool) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for item in observations:
        if item["state"] != "open" and not include_closed:
            continue
        key = (item["address"], item["protocol"], int(item["port"]))
        grouped.setdefault(key, []).append(item)
    results = []
    for (address, protocol, port), items in sorted(grouped.items()):
        sources = sorted({item["source"] for item in items})
        source_types = {item["source_type"] for item in items}
        active_verified = "tcp_connect" in sources
        passive_only = not active_verified
        agreement = "consistent" if len(source_types) > 1 else ("active_only" if active_verified else "passive_only")
        confidence = min(max(float(item.get("confidence", 0.0)) for item in items) + 0.05 * (len(sources) - 1), 0.98)
        hostnames = sorted({host for item in items for host in item.get("hostnames", [])})
        results.append({
            "type": "port_result",
            "address": address,
            "port": port,
            "protocol": protocol,
            "state": "open",
            "service": guess_service(port),
            "sources": sources,
            "source_details": [{"source": item["source"], "source_type": item["source_type"], "evidence": item.get("raw", {})} for item in items],
            "source_count": len(sources),
            "source_agreement": agreement,
            "passive_only": passive_only,
            "active_verified": active_verified,
            "conflict": False,
            "conflict_reason": None,
            "confidence": round(confidence, 3),
            "hostnames": hostnames[:16],
            "evidence": {"summary": f"Port {port}/tcp on {address} observed as open from {', '.join(sources)}.", "items": []},
        })
    return results


def build_output(root_domain: str, mode: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], addresses: list[dict[str, Any]], ports: list[int], active_requested: bool, probe_count: int, status: str = "completed", reason: str | None = None) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": "domain", "value": root_domain},
        "mode": mode,
        "results": results,
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "status": status,
            "reason": reason,
            "target_count": len(addresses),
            "port_count": len(ports),
            "result_count": len(results),
            "passive_sources": [],
            "active_enabled": active_requested,
            "estimated_port_probes": len(addresses) * len(ports) if active_requested else 0,
            "requires_active_verify": active_requested,
            "requires_high_risk": False,
            "requires_approval": False,
            "source_status_count": len(source_status),
            "error_count": len(errors),
            "authorization_scope": authorization_scope,
        },
        "errors": errors[:MAX_ERRORS],
        "safety": {
            "target_type_domain_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": active_requested,
            "high_risk_policy_allowed": False,
            "tcp_connect_probes": probe_count,
            "syn_probe_attempts": 0,
            "external_scanner_invocations": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
        },
    }


def targets_from_findings(raw_findings: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return []
    targets: dict[str, dict[str, Any]] = {}
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            data = evidence.get("data") if isinstance(evidence, dict) else None
            if not isinstance(data, dict):
                continue
            value = data.get("x-sentinelflow-dns.value")
            record_type = data.get("x-sentinelflow-dns.record_type")
            if record_type not in {"A", "AAAA"} or not isinstance(value, str):
                continue
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not is_public_routable_ip(str(ip)):
                continue
            domain = data.get("x-sentinelflow-dns.domain")
            item = targets.setdefault(str(ip), {"address": str(ip), "hostnames": []})
            if isinstance(domain, str) and domain not in item["hostnames"]:
                item["hostnames"].append(domain)
    return [targets[key] for key in sorted(targets)]


def validate_targets(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise InputError("inputs.addresses must be an array", "$.inputs.addresses")
    targets = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            address = item
            hostnames: list[str] = []
        elif isinstance(item, dict):
            address = str(item.get("address", ""))
            hostnames = clean_string_array(item.get("hostnames", []))
        else:
            raise InputError("address item must be a string or object", f"$.inputs.addresses[{index}]")
        ip = ipaddress.ip_address(address)
        targets.append({"address": str(ip), "hostnames": hostnames})
    return targets


def is_public_routable_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or int(address) == 0xFFFF_FFFF
            or address in ipaddress.ip_network("100.64.0.0/10")
            or address in ipaddress.ip_network("198.18.0.0/15")
        )
    mapped = address.ipv4_mapped
    if mapped is not None:
        return is_public_routable_ip(str(mapped))
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def merge_targets(primary: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for target in primary + extra:
        item = merged.setdefault(target["address"], {"address": target["address"], "hostnames": []})
        item["hostnames"] = sorted(set(item["hostnames"]) | set(target.get("hostnames", [])))[:16]
    return [merged[key] for key in sorted(merged)]


def selected_ports(options: dict[str, Any]) -> list[int]:
    if isinstance(options.get("ports"), list) and options["ports"]:
        raw_ports = options["ports"]
    else:
        raw_ports = PORT_PROFILES.get(str(options.get("port_profile") or "web"), PORT_PROFILES["web"])
    ports = []
    for item in raw_ports:
        port = int(item)
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def observation(address: str, port: int, protocol: str, state: str, source: str, confidence: Any, hostnames: Any, raw: Any) -> dict[str, Any]:
    return {
        "address": address,
        "port": port,
        "protocol": protocol,
        "state": state,
        "source": source,
        "source_type": "active" if source == "tcp_connect" else ("fixture" if source == "fixture" else "passive_intel"),
        "confidence": clamp_float(confidence),
        "hostnames": clean_string_array(hostnames),
        "raw": raw if isinstance(raw, dict) else {},
    }


def guess_service(port: int) -> str:
    return {80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt"}.get(port, "unknown")


def resolve_plugin_file(value: str) -> Path:
    path = Path(value)
    candidate = path if path.is_absolute() else PLUGIN_ROOT / path
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(PLUGIN_ROOT)
    if not resolved.is_file():
        raise InputError("file path must point to a regular file", "$.options.passive_intel.local_cache_file")
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


def list_of_strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def clean_string_array(value: Any) -> list[str]:
    return [str(item)[:253] for item in value if isinstance(item, str) and item.strip()][:16] if isinstance(value, list) else []


def string_or(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    return float(value) if isinstance(value, (int, float)) and minimum <= float(value) <= maximum else default


def clamp_float(value: Any) -> float:
    try:
        return min(max(float(value), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.0


def standard_error(code: str, message: str, field: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details or {}}
    if field:
        error["field"] = field
    return error


def safe_message(error: BaseException) -> str:
    return str(error).replace("\n", " ").strip()[:512] or error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(main())
