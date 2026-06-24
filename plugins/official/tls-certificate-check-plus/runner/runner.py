#!/usr/bin/env python3
"""Passive-first bounded TLS certificate inspection for SentinelFlow."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "tls-certificate-check-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SOURCE_BASE_CONFIDENCE = {"fixture": 0.72, "local_cache": 0.72, "tls_handshake": 0.90}
NOW = dt.datetime(2026, 6, 17, tzinfo=dt.timezone.utc)


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
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "active_tls", "hybrid"}:
        raise InputError("unsupported TLS certificate mode", "$.options.mode")
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    checks = object_at(options, "checks", "$.options.checks")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")
    endpoints = merge_endpoints(validate_endpoints(inputs.get("endpoints", [])), endpoints_from_findings(inputs.get("findings", [])))
    max_endpoints = bounded_int(active_options.get("max_endpoints"), 100, 1, 1000)
    if len(endpoints) > max_endpoints:
        endpoints = endpoints[:max_endpoints]
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    active_requested = mode == "active_tls" or (mode == "hybrid" and bool(active_options.get("enabled")))
    if active_requested:
        errors.append(standard_error("P7_SCOPE_DISABLED", "TLS handshake inspection is disabled in P5.6", "$.options.active.enabled", {"mode": mode}))

    lab_profile = options.get("execution_profile") == "lab"
    if mode != "fixture" and not lab_profile:
        endpoints = [endpoint for endpoint in endpoints if endpoint_is_public(endpoint)]

    if mode == "dry_run":
        return build_output(root_domain, mode, authorization_scope, [], source_status, errors, endpoints, active_requested, 0)
    if mode in {"fixture", "passive_intel", "hybrid"}:
        observations.extend(run_passive_sources(passive_options, endpoints, source_status))
    if active_requested:
        source_status.append({"source": "tls_handshake", "status": "skipped_p7_disabled", "message": "TLS handshake inspection was not executed in P5.6.", "probe_count": 0, "query_count": 0})

    results = merge_results([build_result(item, checks) for item in observations])
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    return build_output(root_domain, mode, authorization_scope, results[:MAX_RESULTS], source_status, errors, endpoints, active_requested, sum(int(item.get("probe_count", 0)) for item in source_status))


def run_passive_sources(options: dict[str, Any], endpoints: list[dict[str, Any]], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for source in list_of_strings(options.get("sources", [])):
        if source == "fixture":
            observations.extend(load_file_source("fixture", string_or(options.get("fixture_file"), "examples/fixture.tls.example.com.json"), endpoints, source_status))
        if source == "local_cache":
            observations.extend(load_file_source("local_cache", string_or(options.get("local_cache_file"), "examples/cache.empty.json"), endpoints, source_status))
    return observations


def load_file_source(source: str, path: str, endpoints: list[dict[str, Any]], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        allowed = {(item["host"], item["port"]) for item in endpoints}
        observations = []
        for item in data.get("certificates", []):
            if not isinstance(item, dict):
                continue
            host = str(item.get("host", "")).lower()
            port = int(item.get("port", 443))
            if (host, port) not in allowed:
                continue
            observations.append(observation_from_mapping(item, source))
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_active_tls(endpoints: list[dict[str, Any]], options: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeout = bounded_float(options.get("timeout_seconds"), 2.0, 0.2, 10.0)
    concurrency = bounded_int(options.get("concurrency"), 4, 1, 20)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 5, 1, 20)
    limiter = RateLimiter(rate_limit)
    probe_count = 0

    def probe(endpoint: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal probe_count
        probe_count += 1
        limiter.wait()
        try:
            return inspect_tls(endpoint, timeout)
        except (OSError, ssl.SSLError, ValueError):
            return None

    observations: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(probe, endpoint) for endpoint in endpoints]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                observations.append(item)
    source_status.append({"source": "tls_handshake", "status": "ok", "message": "TLS handshake inspection completed.", "query_count": 0, "probe_count": probe_count})
    return observations


def inspect_tls(endpoint: dict[str, Any], timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    server_name = endpoint.get("server_name") or endpoint["host"]
    with socket.create_connection((endpoint["host"], endpoint["port"]), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as sock:
            certificate = sock.getpeercert()
            item = {
                "host": endpoint["host"],
                "port": endpoint["port"],
                "subject": name_to_string(certificate.get("subject", [])),
                "issuer": name_to_string(certificate.get("issuer", [])),
                "san": [value for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"],
                "not_before": parse_cert_time(certificate.get("notBefore")),
                "not_after": parse_cert_time(certificate.get("notAfter")),
                "signature_algorithm": None,
                "tls_version": sock.version(),
                "chain": [],
                "confidence": SOURCE_BASE_CONFIDENCE["tls_handshake"],
            }
            return observation_from_mapping(item, "tls_handshake")


def build_result(item: dict[str, Any], checks: dict[str, Any]) -> dict[str, Any]:
    not_after = parse_iso(item["not_after"])
    days_until_expiry = (not_after - NOW).days if not_after else None
    warning_days = bounded_int(checks.get("expiry_warning_days"), 30, 1, 365)
    if days_until_expiry is None:
        status = "unknown"
    elif days_until_expiry < 0:
        status = "expired"
    elif days_until_expiry <= warning_days:
        status = "expires_soon"
    else:
        status = "valid"
    return {
        "type": "tls_certificate_result",
        "host": item["host"],
        "port": item["port"],
        "subject": item["subject"],
        "issuer": item["issuer"],
        "san": item["san"],
        "not_before": item["not_before"],
        "not_after": item["not_after"],
        "days_until_expiry": days_until_expiry,
        "status": status,
        "signature_algorithm": item.get("signature_algorithm"),
        "tls_version": item.get("tls_version"),
        "chain_summary": item.get("chain", []) if bool(checks.get("include_chain_summary")) else [],
        "san_assets": item["san"] if bool(checks.get("include_san_assets")) else [],
        "sources": [item["source"]],
        "source_count": 1,
        "source_details": [{"source": item["source"], "source_type": item["source_type"], "evidence": item["raw"]}],
        "confidence": item["confidence"],
        "evidence": {"summary": f"TLS certificate for {item['host']}:{item['port']} is {status}.", "items": []},
    }


def merge_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    for result in results:
        grouped.setdefault((result["host"], result["port"], result["subject"]), []).append(result)
    merged = []
    for (_host, _port, _subject), items in sorted(grouped.items()):
        selected = max(items, key=lambda item: item["confidence"])
        sources = sorted({source for item in items for source in item["sources"]})
        source_details = [detail for item in items for detail in item["source_details"]]
        selected.update({"sources": sources, "source_count": len(sources), "source_details": source_details, "confidence": min(selected["confidence"] + 0.04 * (len(sources) - 1), 0.98)})
        merged.append(selected)
    return merged


def build_output(root_domain: str, mode: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], endpoints: list[dict[str, Any]], active_requested: bool, probe_count: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": "domain", "value": root_domain},
        "mode": mode,
        "results": results,
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "endpoint_count": len(endpoints),
            "result_count": len(results),
            "active_enabled": active_requested,
            "estimated_tls_handshakes": len(endpoints) if active_requested else 0,
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
            "active_tls_handshakes": probe_count,
            "port_scans": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
            "dos_attempts": 0,
        },
    }


def endpoints_from_findings(raw_findings: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return []
    endpoints = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            data = evidence.get("data") if isinstance(evidence, dict) else None
            if not isinstance(data, dict):
                continue
            url = data.get("x-sentinelflow-http.url")
            tls_enabled = data.get("x-sentinelflow-http.tls_enabled")
            if isinstance(url, str) and tls_enabled is True:
                parsed = __import__("urllib.parse").parse.urlparse(url)
                if parsed.hostname:
                    endpoints.append({"host": parsed.hostname, "port": parsed.port or 443, "server_name": parsed.hostname})
    return endpoints


def validate_endpoints(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise InputError("inputs.endpoints must be an array", "$.inputs.endpoints")
    endpoints = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise InputError("endpoint item must be an object", f"$.inputs.endpoints[{index}]")
        host = str(item.get("host", "")).strip().lower()
        if not host:
            raise InputError("endpoint.host must be non-empty", f"$.inputs.endpoints[{index}].host")
        endpoints.append({"host": host, "port": int(item.get("port", 443)), "server_name": str(item.get("server_name") or host)})
    return endpoints


def merge_endpoints(primary: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {(item["host"], item["port"]): item for item in primary + extra}
    return [merged[key] for key in sorted(merged)]


def endpoint_is_public(endpoint: dict[str, Any]) -> bool:
    try:
        return is_public_routable_ip(socket.gethostbyname(endpoint["host"]))
    except OSError:
        return False


def is_public_routable_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified)


def observation_from_mapping(item: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "host": str(item.get("host", "")).lower(),
        "port": int(item.get("port", 443)),
        "subject": truncate(item.get("subject")) or "",
        "issuer": truncate(item.get("issuer")) or "",
        "san": clean_string_array(item.get("san", [])),
        "not_before": normalize_time(item.get("not_before")),
        "not_after": normalize_time(item.get("not_after")),
        "signature_algorithm": truncate(item.get("signature_algorithm")),
        "tls_version": truncate(item.get("tls_version")),
        "chain": item.get("chain", []) if isinstance(item.get("chain"), list) else [],
        "confidence": clamp_float(item.get("confidence", SOURCE_BASE_CONFIDENCE.get(source, 0.7))),
        "source": source,
        "source_type": "active" if source == "tls_handshake" else ("fixture" if source == "fixture" else "passive_intel"),
        "raw": item,
    }


def name_to_string(value: Any) -> str:
    parts = []
    for group in value:
        for key, val in group:
            parts.append(f"{key}={val}")
    return ",".join(parts)


def parse_cert_time(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    parsed = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_time(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    return ""


def parse_iso(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


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
    return [str(item)[:253] for item in value if isinstance(item, str) and item.strip()][:128] if isinstance(value, list) else []


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


def truncate(value: Any, limit: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.replace("\r", " ").replace("\n", " ").strip()[:limit]


def standard_error(code: str, message: str, field: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    error = {"code": code, "message": message, "details": details or {}}
    if field:
        error["field"] = field
    return error


def safe_message(error: BaseException) -> str:
    return str(error).replace("\n", " ").strip()[:512] or error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(main())
