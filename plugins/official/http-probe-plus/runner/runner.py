#!/usr/bin/env python3
"""Passive-first bounded HTTP probing for SentinelFlow."""

from __future__ import annotations

import concurrent.futures
import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "http-probe-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
SOURCE_BASE_CONFIDENCE = {"fixture": 0.70, "local_cache": 0.70, "http_head": 0.85, "http_get": 0.88}
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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
    endpoints = merge_endpoints(validate_endpoints(inputs.get("endpoints", [])), endpoints_from_findings(inputs.get("findings", [])))
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "active_safe", "hybrid"}:
        raise InputError("unsupported HTTP probe mode", "$.options.mode")
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    active_options = object_at(options, "active", "$.options.active")
    output_options = object_at(options, "output", "$.options.output")
    policy = object_at(payload, "policy", "$.policy")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    active_requested = mode == "active_safe" or (mode == "hybrid" and bool(active_options.get("enabled")))

    max_endpoints = bounded_int(active_options.get("max_endpoints"), 100, 1, 1000)
    if len(endpoints) > max_endpoints:
        errors.append(standard_error("InputLimitExceeded", "endpoint count exceeds active.max_endpoints", "$.inputs.endpoints", {"endpoint_count": len(endpoints), "max_endpoints": max_endpoints}))
        endpoints = endpoints[:max_endpoints]
    if active_requested:
        errors.append(standard_error("P7_SCOPE_DISABLED", "HTTP probing is disabled in P5.6", "$.options.active.enabled", {"mode": mode, "activeEnabled": True}))

    lab_profile = options.get("execution_profile") == "lab"
    if mode != "fixture" and not lab_profile:
        endpoints = [endpoint for endpoint in endpoints if endpoint_is_public(endpoint)]

    if mode == "dry_run":
        return build_output(root_domain, mode, authorization_scope, [], source_status, errors, endpoints, active_requested, 0)

    if mode in {"fixture", "passive_intel", "hybrid"}:
        observations.extend(run_passive_sources(passive_options, endpoints, source_status))
    if active_requested:
        source_status.append({"source": "http_probe", "status": "skipped_p7_disabled", "message": "HTTP probing was not executed in P5.6.", "probe_count": 0, "query_count": 0})

    results = merge_observations(observations)
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    if not bool(output_options.get("include_conflicts")):
        for result in results:
            result["conflict"] = False
            result["conflict_reason"] = None
    return build_output(root_domain, mode, authorization_scope, results[:MAX_RESULTS], source_status, errors, endpoints, active_requested, sum(int(item.get("probe_count", 0)) for item in source_status))


def run_passive_sources(options: dict[str, Any], endpoints: list[dict[str, Any]], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources = list_of_strings(options.get("sources", []))
    observations: list[dict[str, Any]] = []
    if "fixture" in sources:
        observations.extend(load_file_source("fixture", string_or(options.get("fixture_file"), "examples/fixture.http.example.com.json"), endpoints, source_status))
    if "local_cache" in sources:
        observations.extend(load_file_source("local_cache", string_or(options.get("local_cache_file"), "examples/cache.empty.json"), endpoints, source_status))
    return observations


def load_file_source(source: str, path: str, endpoints: list[dict[str, Any]], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        allowed_urls = {endpoint["url"] for endpoint in endpoints}
        observations = []
        for item in data.get("endpoints", []):
            if not isinstance(item, dict):
                continue
            url = normalize_url(str(item.get("url", "")))
            if url not in allowed_urls:
                continue
            observations.append(observation(url, item.get("status_code"), item, source, item.get("confidence", SOURCE_BASE_CONFIDENCE[source])))
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_active_http(endpoints: list[dict[str, Any]], options: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeout = bounded_float(options.get("timeout_seconds"), 2.0, 0.2, 10.0)
    concurrency = bounded_int(options.get("concurrency"), 4, 1, 20)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 5, 1, 20)
    max_redirects = bounded_int(options.get("max_redirects"), 3, 0, 5)
    max_response_bytes = bounded_int(options.get("max_response_bytes"), 65536, 0, 262144)
    methods = set(list_of_strings(options.get("methods", [])))
    limiter = RateLimiter(rate_limit)
    probe_count = 0

    def probe(endpoint: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal probe_count
        probe_count += 1
        limiter.wait()
        return probe_url(endpoint["url"], timeout, max_redirects, max_response_bytes, "GET" if "GET" in methods else "HEAD")

    observations: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(probe, endpoint) for endpoint in endpoints]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item:
                observations.append(item)
    source_status.append({"source": "http_probe", "status": "ok", "message": "HTTP probing completed.", "probe_count": probe_count, "query_count": 0})
    return observations


def probe_url(url: str, timeout: float, max_redirects: int, max_response_bytes: int, method: str) -> dict[str, Any] | None:
    current = url
    redirects: list[str] = []
    for _ in range(max_redirects + 1):
        parsed = urlparse(current)
        connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = connection_class(parsed.hostname, parsed.port, timeout=timeout, context=ssl.create_default_context()) if parsed.scheme == "https" else connection_class(parsed.hostname, parsed.port, timeout=timeout)
        path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
        try:
            conn.request(method, path, headers={"User-Agent": "SentinelFlow-http-probe-plus/0.1"})
            response = conn.getresponse()
            body = response.read(max_response_bytes) if method == "GET" and max_response_bytes > 0 else b""
            location = response.getheader("Location")
            if response.status in {301, 302, 303, 307, 308} and location and len(redirects) < max_redirects:
                current = normalize_url(location if "://" in location else urlunparse((parsed.scheme, parsed.netloc, location, "", "", "")))
                redirects.append(current)
                continue
            raw = {
                "url": url,
                "status_code": response.status,
                "title": extract_title(body),
                "server": truncate(response.getheader("Server")),
                "content_type": truncate(response.getheader("Content-Type")),
                "content_length": int(response.getheader("Content-Length")) if str(response.getheader("Content-Length") or "").isdigit() else len(body) if body else None,
                "redirect_chain": redirects,
                "tls_enabled": parsed.scheme == "https",
            }
            return observation(url, response.status, raw, "http_get" if method == "GET" else "http_head", SOURCE_BASE_CONFIDENCE["http_get" if method == "GET" else "http_head"])
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return None
        finally:
            conn.close()
    return None


def merge_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in observations:
        grouped.setdefault(item["url"], []).append(item)
    results = []
    for url, items in sorted(grouped.items()):
        sources = sorted({item["source"] for item in items})
        active_verified = any(item["source_type"] == "active" for item in items)
        selected = max(items, key=lambda item: item.get("confidence", 0.0))
        source_types = {item["source_type"] for item in items}
        agreement = "consistent" if len(source_types) > 1 else ("active_only" if active_verified else "passive_only")
        confidence = min(max(float(item.get("confidence", 0.0)) for item in items) + 0.05 * (len(sources) - 1), 0.98)
        results.append({
            "type": "http_result",
            "url": url,
            "status_code": selected.get("status_code"),
            "title": selected.get("title"),
            "server": selected.get("server"),
            "content_type": selected.get("content_type"),
            "content_length": selected.get("content_length"),
            "redirect_chain": selected.get("redirect_chain", []),
            "tls_enabled": bool(selected.get("tls_enabled")),
            "sources": sources,
            "source_details": [{"source": item["source"], "source_type": item["source_type"], "evidence": item.get("raw", {})} for item in items],
            "source_count": len(sources),
            "source_agreement": agreement,
            "passive_only": not active_verified,
            "active_verified": active_verified,
            "conflict": False,
            "conflict_reason": None,
            "confidence": round(confidence, 3),
            "evidence": {"summary": f"HTTP endpoint {url} observed with status {selected.get('status_code')}.", "items": []},
        })
    return results


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
            "estimated_http_probes": len(endpoints) if active_requested else 0,
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
            "active_http_probes": probe_count,
            "path_bruteforce_attempts": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
            "dos_attempts": 0,
        },
    }


def endpoints_from_findings(raw_findings: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return []
    endpoints: list[dict[str, Any]] = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            data = evidence.get("data") if isinstance(evidence, dict) else None
            if not isinstance(data, dict):
                continue
            address = data.get("x-sentinelflow-port.address")
            port = data.get("x-sentinelflow-port.port")
            state = data.get("x-sentinelflow-port.state")
            if not isinstance(address, str) or not isinstance(port, int) or state != "open":
                continue
            if port in {80, 8080, 8000, 8888, 3000, 5000, 9000}:
                endpoints.append({"url": normalize_url(f"http://{address}:{port}/")})
            if port in {443, 8443}:
                endpoints.append({"url": normalize_url(f"https://{address}:{port}/")})
    return endpoints


def validate_endpoints(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise InputError("inputs.endpoints must be an array", "$.inputs.endpoints")
    endpoints = []
    for index, item in enumerate(raw):
        raw_url = item if isinstance(item, str) else item.get("url") if isinstance(item, dict) else None
        if not isinstance(raw_url, str):
            raise InputError("endpoint item must be a string or object", f"$.inputs.endpoints[{index}]")
        endpoints.append({"url": normalize_url(raw_url)})
    return endpoints


def merge_endpoints(primary: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {item["url"]: item for item in primary + extra}
    return [merged[key] for key in sorted(merged)]


def normalize_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise InputError("endpoint URL must be http or https", "$.inputs.endpoints")
    path = parsed.path or "/"
    netloc = parsed.netloc.lower()
    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def endpoint_is_public(endpoint: dict[str, Any]) -> bool:
    parsed = urlparse(endpoint["url"])
    host = parsed.hostname or ""
    try:
        return is_public_routable_ip(socket.gethostbyname(host))
    except OSError:
        return False


def is_public_routable_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified)


def observation(url: str, status_code: Any, raw: dict[str, Any], source: str, confidence: Any) -> dict[str, Any]:
    parsed = urlparse(url)
    return {
        "url": url,
        "status_code": int(status_code) if isinstance(status_code, int) else None,
        "title": truncate(raw.get("title")),
        "server": truncate(raw.get("server")),
        "content_type": truncate(raw.get("content_type")),
        "content_length": raw.get("content_length") if isinstance(raw.get("content_length"), int) else None,
        "redirect_chain": clean_string_array(raw.get("redirect_chain", [])),
        "tls_enabled": bool(raw.get("tls_enabled", parsed.scheme == "https")),
        "source": source,
        "source_type": "active" if source in {"http_head", "http_get"} else ("fixture" if source == "fixture" else "passive_intel"),
        "confidence": clamp_float(confidence),
        "raw": raw,
    }


def extract_title(body: bytes) -> str | None:
    match = TITLE_RE.search(body[:65536])
    if not match:
        return None
    text = html.unescape(match.group(1).decode("utf-8", "ignore"))
    return truncate(" ".join(text.split()))


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
    return [str(item)[:2048] for item in value if isinstance(item, str) and item.strip()][:16] if isinstance(value, list) else []


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
