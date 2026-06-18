#!/usr/bin/env python3
"""Passive Web technology fingerprinting for SentinelFlow."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "web-fingerprint-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000

SIGNATURES = [
    {"technology": "WordPress", "category": "cms", "patterns": ["wordpress", "wp-content", "wp-includes"], "confidence": 0.82},
    {"technology": "Drupal", "category": "cms", "patterns": ["drupal", "x-drupal"], "confidence": 0.80},
    {"technology": "Grafana", "category": "web_app", "patterns": ["grafana", "grafanabootdata"], "confidence": 0.86},
    {"technology": "React", "category": "js_framework", "patterns": ["react", "__react", "data-reactroot"], "confidence": 0.70},
    {"technology": "Vue.js", "category": "js_framework", "patterns": ["vue.js", "__vue__", "data-v-"], "confidence": 0.70},
    {"technology": "nginx", "category": "middleware", "patterns": ["nginx"], "confidence": 0.74},
    {"technology": "Apache HTTP Server", "category": "middleware", "patterns": ["apache"], "confidence": 0.74},
    {"technology": "PHP", "category": "runtime", "patterns": ["php/"], "confidence": 0.72},
    {"technology": "Cloudflare", "category": "cdn_waf", "patterns": ["cloudflare", "cf-cache-status", "__cf_bm"], "confidence": 0.78},
]


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
    if target.get("type") != "domain":
        raise InputError("target.type must be domain", "$.target.type")
    root_domain = string_at(target, "value", "$.target.value").strip().lower().rstrip(".")
    inputs = object_at(payload, "inputs", "$.inputs")
    options = object_at(payload, "options", "$.options")
    mode = string_at(options, "mode", "$.options.mode")
    if mode not in {"fixture", "dry_run", "passive_intel", "from_http_probe"}:
        raise InputError("unsupported Web fingerprint mode", "$.options.mode")
    passive_options = object_at(options, "passive_intel", "$.options.passive_intel")
    fingerprint_options = object_at(options, "fingerprint", "$.options.fingerprint")
    output_options = object_at(options, "output", "$.options.output")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    observations = normalize_observations(inputs.get("observations", []), "input")
    observations.extend(observations_from_findings(inputs.get("findings", [])))
    if mode in {"fixture", "passive_intel"}:
        observations.extend(load_passive_sources(passive_options, source_status))

    if mode == "dry_run":
        return build_output(root_domain, mode, authorization_scope, [], source_status, errors, len(observations))

    results = merge_results(fingerprint_observations(observations, fingerprint_options))
    if not bool(output_options.get("include_signal_details")):
        for result in results:
            result["signals"] = []
    if not bool(output_options.get("include_source_details")):
        for result in results:
            result["source_details"] = []
    return build_output(root_domain, mode, authorization_scope, results[:MAX_RESULTS], source_status, errors, len(observations))


def load_passive_sources(options: dict[str, Any], source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for source in list_of_strings(options.get("sources", [])):
        if source == "fixture":
            observations.extend(load_file_source("fixture", string_or(options.get("fixture_file"), "examples/fixture.web.example.com.json"), source_status))
        if source == "local_cache":
            observations.extend(load_file_source("local_cache", string_or(options.get("local_cache_file"), "examples/cache.empty.json"), source_status))
    return observations


def load_file_source(source: str, path: str, source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        observations = normalize_observations(data.get("observations", []), source)
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def fingerprint_observations(observations: list[dict[str, Any]], options: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for observation in observations:
        text = searchable_text(observation, options)
        for signature in SIGNATURES:
            matched = [pattern for pattern in signature["patterns"] if pattern in text]
            if not matched:
                continue
            confidence = min(float(signature["confidence"]) + 0.03 * (len(matched) - 1) + 0.03 * float(observation.get("confidence", 0.0)), 0.98)
            signals = [{"kind": signal_kind(pattern, observation), "pattern": pattern, "source": observation["source"]} for pattern in matched]
            findings.append({
                "type": "web_fingerprint_result",
                "url": observation["url"],
                "technology": signature["technology"],
                "category": signature["category"],
                "version": extract_version(signature["technology"], observation),
                "confidence": round(confidence, 3),
                "sources": [observation["source"]],
                "source_details": [{"source": observation["source"], "source_type": observation["source_type"], "evidence": observation["raw"]}],
                "signals": signals,
                "signal_count": len(signals),
                "evidence": {"summary": f"{signature['technology']} fingerprint observed on {observation['url']}.", "items": []},
            })
    return findings


def merge_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for result in results:
        grouped.setdefault((result["url"], result["technology"]), []).append(result)
    merged = []
    for (url, technology), items in sorted(grouped.items()):
        selected = max(items, key=lambda item: item["confidence"])
        sources = sorted({source for item in items for source in item["sources"]})
        signals = [signal for item in items for signal in item["signals"]]
        source_details = [detail for item in items for detail in item["source_details"]]
        selected.update({
            "url": url,
            "technology": technology,
            "sources": sources,
            "source_count": len(sources),
            "source_details": source_details,
            "signals": signals[:32],
            "signal_count": len(signals),
            "confidence": min(selected["confidence"] + 0.03 * (len(sources) - 1), 0.98),
        })
        merged.append(selected)
    return merged


def build_output(root_domain: str, mode: str, authorization_scope: str, results: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], observation_count: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "target": {"type": "domain", "value": root_domain},
        "mode": mode,
        "results": results,
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
            "target_type_domain_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": False,
            "high_risk_policy_allowed": False,
            "active_http_requests": 0,
            "path_bruteforce_attempts": 0,
            "exploit_attempts": 0,
            "bruteforce_attempts": 0,
            "dos_attempts": 0,
        },
    }


def observations_from_findings(raw_findings: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return []
    observations = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            data = evidence.get("data") if isinstance(evidence, dict) else None
            if not isinstance(data, dict):
                continue
            url = data.get("x-sentinelflow-http.url")
            if not isinstance(url, str):
                continue
            observations.append(observation_from_mapping({
                "url": url,
                "title": data.get("x-sentinelflow-http.title"),
                "server": data.get("x-sentinelflow-http.server"),
                "content_type": data.get("x-sentinelflow-http.content_type"),
                "headers": {},
                "body_signals": [],
                "confidence": data.get("confidence", 0.7),
            }, "http_probe_finding"))
    return observations


def normalize_observations(raw: Any, source: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise InputError("observations must be an array", "$.inputs.observations")
    return [observation_from_mapping(item, source) for item in raw if isinstance(item, dict)]


def observation_from_mapping(item: dict[str, Any], source: str) -> dict[str, Any]:
    url = normalize_url(str(item.get("url", "")))
    return {
        "url": url,
        "title": truncate(item.get("title")),
        "server": truncate(item.get("server")),
        "content_type": truncate(item.get("content_type")),
        "headers": clean_mapping(item.get("headers", {})),
        "body_signals": clean_string_array(item.get("body_signals", [])),
        "favicon_hash": truncate(item.get("favicon_hash")),
        "confidence": clamp_float(item.get("confidence", 0.7)),
        "source": source,
        "source_type": "fixture" if source == "fixture" else ("passive_intel" if source in {"local_cache", "http_probe_finding"} else "input"),
        "raw": item,
    }


def searchable_text(observation: dict[str, Any], options: dict[str, Any]) -> str:
    parts = []
    if bool(options.get("use_title")):
        parts.append(observation.get("title") or "")
    if bool(options.get("use_headers")):
        parts.extend([observation.get("server") or "", observation.get("content_type") or ""])
        parts.extend([f"{key}: {value}" for key, value in observation.get("headers", {}).items()])
    if bool(options.get("use_body_signals")):
        max_bytes = bounded_int(options.get("max_body_signal_bytes"), 65536, 0, 65536)
        parts.extend(signal[:max_bytes] for signal in observation.get("body_signals", []))
    if bool(options.get("use_favicon_hash")):
        parts.append(observation.get("favicon_hash") or "")
    return "\n".join(parts).lower()


def signal_kind(pattern: str, observation: dict[str, Any]) -> str:
    lower = pattern.lower()
    headers = "\n".join([observation.get("server") or "", observation.get("content_type") or "", *[f"{key}: {value}" for key, value in observation.get("headers", {}).items()]]).lower()
    if lower in headers:
        return "header"
    if lower in (observation.get("title") or "").lower():
        return "title"
    if lower in (observation.get("favicon_hash") or "").lower():
        return "favicon_hash"
    return "body"


def extract_version(technology: str, observation: dict[str, Any]) -> str | None:
    text = searchable_text(observation, {"use_title": True, "use_headers": True, "use_body_signals": True, "use_favicon_hash": False, "max_body_signal_bytes": 65536})
    if technology == "WordPress":
        match = re.search(r"wordpress[ /]([0-9][0-9.]+)", text)
        return match.group(1) if match else None
    if technology == "PHP":
        match = re.search(r"php/([0-9][0-9.]+)", text)
        return match.group(1) if match else None
    return None


def normalize_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise InputError("observation URL must be http or https", "$.inputs.observations")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


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
    return [str(item)[:2048] for item in value if isinstance(item, str) and item.strip()][:64] if isinstance(value, list) else []


def clean_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).lower()[:128]: str(item)[:512] for key, item in value.items() if isinstance(key, str) and item is not None}


def string_or(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    return value if isinstance(value, int) and minimum <= value <= maximum else default


def clamp_float(value: Any) -> float:
    try:
        return min(max(float(value), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.0


def truncate(value: Any, limit: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.replace("\r", " ").replace("\n", " ").strip()[:limit]


def safe_message(error: BaseException) -> str:
    return str(error).replace("\n", " ").strip()[:512] or error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(main())
