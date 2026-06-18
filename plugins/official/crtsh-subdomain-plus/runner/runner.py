#!/usr/bin/env python3
"""Passive crt.sh-style certificate transparency import for SentinelFlow."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "crtsh-subdomain-plus"
MAX_ERRORS = 50
MAX_RESULTS = 10000
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)


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
        raise InputError("unsupported crt.sh import mode", "$.options.mode")
    domain = normalize_domain(string_at(target, "value", "$.target.value"))
    if string_at(target, "type", "$.target.type") != "domain":
        raise InputError("target.type must be domain", "$.target.type")
    lookup = object_at(options, "lookup", "$.options.lookup")
    local_cache = object_at(options, "local_cache", "$.options.local_cache")
    provider = object_at(options, "provider", "$.options.provider")
    output_options = object_at(options, "output", "$.options.output")
    source_status: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    if mode == "dry_run":
        return build_output(domain, mode, authorization_scope, [], [], source_status, errors, 0, 0, 0)
    if mode == "fixture":
        observations.extend(load_file_source("passive_crtsh_fixture", string_or(local_cache.get("fixture_file"), "examples/fixture.crtsh.example.com.json"), domain, source_status))
    if mode in {"local_cache", "hybrid"} and bool(local_cache.get("enabled")):
        observations.extend(load_file_source("passive_crtsh_cache", string_or(local_cache.get("cache_file"), "examples/cache.empty.json"), domain, source_status))
    if mode in {"api_lookup", "hybrid"} and bool(provider.get("enabled")):
        observations.extend(run_provider_lookup(provider, domain, source_status))

    include_expired = bool(lookup.get("include_expired"))
    include_wildcard = bool(lookup.get("include_wildcard"))
    include_certificate_assets = bool(lookup.get("include_certificate_assets")) and bool(output_options.get("include_certificate_assets"))
    max_results = bounded_int(lookup.get("max_results"), 100, 0, MAX_RESULTS)
    filtered = [item for item in observations if include_expired or not item["expired"]]
    findings, wildcard_cleaned, discarded_names = build_subdomain_findings(filtered, domain, include_wildcard)
    certificates = build_certificate_assets(filtered, domain) if include_certificate_assets else []
    findings = findings[:max_results]
    certificates = certificates[:max_results]
    if not bool(output_options.get("include_source_details")):
        for item in findings:
            item["source_details"] = []
        for item in certificates:
            item["source_details"] = []
    return build_output(domain, mode, authorization_scope, findings, certificates, source_status, errors, len(observations), wildcard_cleaned, discarded_names)


def load_file_source(source: str, path: str, domain: str, source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        resolved = resolve_plugin_file(path)
        with resolved.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        observations = [observation_from_mapping(item, source, domain) for item in data.get("results", []) if isinstance(item, dict)]
        observations = [item for item in observations if item["san_names"]]
        source_status.append({"source": source, "status": "ok", "message": f"{source} loaded.", "query_count": 0, "probe_count": 0})
        return observations
    except Exception as error:
        source_status.append({"source": source, "status": "error", "message": safe_message(error), "query_count": 0, "probe_count": 0})
        return []


def run_provider_lookup(provider: dict[str, Any], domain: str, source_status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    status = "skipped_unavailable" if bool(provider.get("allow_unavailable")) else "error_unavailable"
    source_status.append({
        "source": "crtsh_api",
        "status": status,
        "message": "crt.sh provider facade is reserved for configured deployments; no external query is executed by the fixture runner.",
        "query_count": 0,
        "probe_count": 0,
        "query_scope": "domain",
        "query_value": domain,
    })
    return []


def observation_from_mapping(item: dict[str, Any], source: str, domain: str) -> dict[str, Any]:
    raw_names = []
    common_name = clean_name(item.get("common_name"), domain, include_base=True)
    if common_name:
        raw_names.append(common_name)
    name_value = item.get("name_value", "")
    if isinstance(name_value, str):
        raw_names.extend(name_value.splitlines())
    san_names = []
    wildcard_names = []
    discarded_names = []
    for raw in raw_names:
        cleaned = clean_name(raw, domain, include_base=True)
        if not cleaned:
            if raw:
                discarded_names.append(str(raw)[:253])
            continue
        if str(raw).strip().startswith("*."):
            wildcard_names.append(cleaned)
        if cleaned not in san_names:
            san_names.append(cleaned)
    not_after = truncate(item.get("not_after"))
    return {
        "entry_id": truncate(item.get("entry_id"), 128),
        "issuer_name": truncate(item.get("issuer_name")),
        "common_name": common_name,
        "san_names": san_names,
        "wildcard_names": wildcard_names,
        "discarded_names": discarded_names,
        "not_before": truncate(item.get("not_before")),
        "not_after": not_after,
        "logged_at": truncate(item.get("logged_at")),
        "expired": is_expired(not_after),
        "source": source,
        "raw": item,
    }


def build_subdomain_findings(observations: list[dict[str, Any]], domain: str, include_wildcard: bool) -> tuple[list[dict[str, Any]], int, int]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    wildcard_cleaned = 0
    discarded = 0
    for item in observations:
        discarded += len(item["discarded_names"])
        wildcard_cleaned += len(item["wildcard_names"])
        for name in item["san_names"]:
            if name == domain:
                continue
            if name in item["wildcard_names"] and not include_wildcard:
                continue
            grouped.setdefault(name, []).append(item)
    findings = []
    for subdomain, items in sorted(grouped.items()):
        sources = sorted({item["source"] for item in items})
        first_seen = min((item["logged_at"] for item in items if item["logged_at"]), default=None)
        last_seen = max((item["logged_at"] for item in items if item["logged_at"]), default=None)
        findings.append({
            "type": "subdomain_finding",
            "domain": domain,
            "subdomain": subdomain,
            "source": "passive_crtsh",
            "sources": sources,
            "confirmed": False,
            "resolved": False,
            "record_type": "unknown",
            "addresses": [],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "wildcard_cleaned": any(subdomain in item["wildcard_names"] for item in items),
            "source_count": len(sources),
            "source_details": [{"source": item["source"], "entry_id": item["entry_id"], "issuer_name": item["issuer_name"], "logged_at": item["logged_at"], "wildcard_names": item["wildcard_names"]} for item in items],
            "confidence": min(0.74 + 0.05 * (len(items) - 1), 0.92),
            "evidence": {"summary": f"crt.sh certificate transparency observed {subdomain}.", "items": []},
            "raw": {"entries": [item["entry_id"] for item in items]},
        })
    return findings, wildcard_cleaned, discarded


def build_certificate_assets(observations: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    certificates = []
    for item in observations:
        if not item["san_names"]:
            continue
        certificates.append({
            "type": "certificate_asset",
            "domain": domain,
            "entry_id": item["entry_id"],
            "issuer_name": item["issuer_name"],
            "common_name": item["common_name"],
            "san_names": item["san_names"],
            "not_before": item["not_before"],
            "not_after": item["not_after"],
            "logged_at": item["logged_at"],
            "expired": item["expired"],
            "sources": [item["source"]],
            "source_count": 1,
            "source_details": [{"source": item["source"], "entry_id": item["entry_id"], "wildcard_names": item["wildcard_names"]}],
            "confidence": 0.78 if item["expired"] else 0.84,
            "evidence": {"summary": f"crt.sh certificate entry {item['entry_id']} contains SAN assets for {domain}.", "items": []},
        })
    return sorted(certificates, key=lambda item: str(item.get("entry_id")))


def build_output(domain: str, mode: str, authorization_scope: str, findings: list[dict[str, Any]], certificates: list[dict[str, Any]], source_status: list[dict[str, Any]], errors: list[dict[str, Any]], observation_count: int, wildcard_cleaned: int, discarded_names: int) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "domain": domain,
        "mode": mode,
        "findings": findings[:MAX_RESULTS],
        "certificates": certificates[:MAX_RESULTS],
        "source_status": source_status[:MAX_ERRORS],
        "summary": {
            "domain": domain,
            "mode": mode,
            "observation_count": observation_count,
            "finding_count": len(findings),
            "certificate_count": len(certificates),
            "wildcard_cleaned_count": wildcard_cleaned,
            "discarded_name_count": discarded_names,
            "active_queries": 0,
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
            "active_target_connections": 0,
            "active_dns_queries": 0,
            "dictionary_candidates": 0,
            "brute_force_attempts": 0,
            "port_scan_attempts": 0,
            "exploit_attempts": 0,
            "user_query_allowed": False,
        },
    }


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if any(token in domain for token in ['"', "'", "&&", "||", "\n", "\r", ";", "|", "*"]):
        raise InputError("domain contains unsupported query metacharacters", "$.target.value")
    if not DOMAIN_RE.match(domain):
        raise InputError("target.value must be a valid domain", "$.target.value")
    return domain


def clean_name(value: Any, domain: str, *, include_base: bool) -> str | None:
    if value is None:
        return None
    name = str(value).strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not DOMAIN_RE.match(name):
        return None
    if name == domain:
        return name if include_base else None
    if not name.endswith(f".{domain}"):
        return None
    return name


def is_expired(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed < datetime.now(timezone.utc)


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


def safe_message(error: BaseException) -> str:
    return str(error).replace(str(PLUGIN_ROOT), "<plugin>").replace("\n", " ")[:512]


if __name__ == "__main__":
    raise SystemExit(main())
