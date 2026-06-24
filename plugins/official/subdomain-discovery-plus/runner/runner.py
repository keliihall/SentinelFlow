#!/usr/bin/env python3
"""P5.6 fixture/local subdomain discovery runner for SentinelFlow."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import random
import re
import secrets
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = "subdomain-discovery-plus"
MAX_FINDINGS = 10_000
MAX_RECORDS_PER_NAME = 64
MAX_ERRORS = 50
DOMAIN_RE = re.compile(
    r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
SOURCE_ORDER = {
    "passive_fixture": 0,
    "passive_crtsh": 1,
    "passive_local_cache": 2,
    "passive_dns_cache": 3,
    "passive_fofa": 4,
    "passive_shodan": 5,
    "active_dictionary": 6,
}
SUPPORTED_MODES = {
    "fixture",
    "dry_run",
    "passive_intel",
    "active_dictionary",
    "hybrid",
    # Backward-compatible aliases for pre-existing examples.
    "passive",
    "active",
}
PASSIVE_INTEL_SOURCES = {
    "crtsh",
    "local_cache",
    "passive_dns_cache",
    "fofa",
    "shodan",
    "censys",
    "securitytrails",
    "virustotal",
}
SYNTHETIC_SCOPE = "fixture:local-only"
SYNTHETIC_DOMAINS = {"example.com", "example.org", "example.test"}
QTYPE = {"A": 1, "CNAME": 5, "AAAA": 28}


class InputError(Exception):
    """Controlled validation error."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.field = field


class RateLimiter:
    """Simple process-local rate limiter for candidate scheduling."""

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
    domain = validate_domain(read_path(payload, ["target", "value"], str), "$.target.value")
    if read_path(payload, ["target", "type"], str) != "domain":
        raise InputError("target.type must be domain", "$.target.type")

    context = read_object(payload, "context", "$.context")
    authorization_scope = context.get("authorization_scope")
    if not isinstance(authorization_scope, str) or not authorization_scope.strip():
        raise InputError(
            "context.authorization_scope is required",
            "$.context.authorization_scope",
        )

    options = read_object(payload, "options", "$.options")
    requested_mode = read_string(options, "mode", "$.options.mode").lower()
    if requested_mode not in SUPPORTED_MODES:
        raise InputError("unsupported subdomain discovery mode", "$.options.mode")
    passive_options = read_object(options, "passive", "$.options.passive")
    active_options = read_object(options, "active", "$.options.active")
    output_options = read_object(options, "output", "$.options.output")
    policy = read_object(payload, "policy", "$.policy")
    mode = canonical_mode(requested_mode, passive_options)

    results: dict[str, dict[str, Any]] = {}
    fatal_errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    source_status: list[dict[str, Any]] = []
    active_observations: list[dict[str, Any]] = []
    candidate_count = 0
    active_queries = 0
    wildcard_detected = False
    active_allowed = bool(policy.get("allow_active_verify"))
    passive_sources = list_of_strings(passive_options.get("sources", []))
    fixture_requested = mode == "fixture" or "fixture" in passive_sources
    active_requested = mode == "active_dictionary" or (
        mode == "hybrid" and bool(active_options.get("enabled"))
    )
    passive_requested = mode in {"fixture", "passive_intel", "hybrid"} and bool(
        passive_options.get("enabled")
    )

    if authorization_scope == SYNTHETIC_SCOPE and not is_synthetic_domain(domain):
        fatal_errors.append(
            standard_error(
                "AUTHZ_ERROR",
                "fixture:local-only scope can only be used with local synthetic fixture targets",
                field="$.context.authorization_scope",
                details={"target": domain, "authorization_scope": authorization_scope},
            )
        )
    if fixture_requested:
        fixture_file = read_string(passive_options, "fixture_file", "$.options.passive.fixture_file")
        fixture_error = fixture_domain_error(domain, fixture_file, mode)
        if fixture_error:
            fatal_errors.append(fixture_error)

    if mode == "dry_run":
        candidates = []
        if bool(active_options.get("enabled")):
            try:
                candidates = load_wordlist(
                    domain,
                    read_string(active_options, "wordlist_file", "$.options.active.wordlist_file"),
                    bounded_int(active_options.get("max_candidates"), 100, 1, 10_000),
                )
            except InputError as error:
                warnings.append(safe_message(error))
        return build_output(
            domain,
            mode,
            authorization_scope,
            [],
            [],
            [],
            source_status,
            [],
            warnings,
            candidate_count=len(candidates),
            active_queries=0,
            wildcard_detected=False,
            active_allowed=active_allowed,
            synthetic_fixture=False,
            real_scan=False,
            planned_sources=planned_sources(passive_sources, active_options),
        )

    if fatal_errors:
        return build_output(
            domain,
            mode,
            authorization_scope,
            [],
            [],
            [],
            source_status,
            fatal_errors,
            warnings,
            candidate_count=0,
            active_queries=0,
            wildcard_detected=False,
            active_allowed=active_allowed,
            synthetic_fixture=fixture_requested,
            real_scan=False,
            planned_sources=planned_sources(passive_sources, active_options),
        )

    if passive_requested:
        run_passive(domain, passive_options, results, source_status, warnings)

    if active_requested and not bool(active_options.get("dry_run")):
        fatal_errors.append(
            standard_error(
                "P7_SCOPE_DISABLED",
                "active DNS dictionary verification is disabled in P5.6; use fixture/local mock input until P7",
                field="$.options.active.enabled",
                details={"mode": mode, "activeEnabled": True},
            )
        )
    elif active_requested:
        active_result = run_active(
            domain,
            active_options,
            output_options,
            results,
            active_observations,
            source_status,
            warnings,
        )
        candidate_count = active_result["candidate_count"]
        active_queries = active_result["active_queries"]
        wildcard_detected = active_result["wildcard_detected"]
    elif mode in {"active_dictionary", "hybrid"}:
        candidate_count = 0

    if not is_synthetic_domain(domain):
        for subdomain, entry in list(results.items()):
            if set(entry.get("sources", set())) == {"passive_fixture"}:
                warnings.append(
                    f"discarded fixture-only observation for real target: {subdomain}"
                )
                del results[subdomain]

    findings, candidates, invalid_observations = classify_observations(
        domain,
        results,
        active_observations,
        include_unresolved=bool(output_options.get("include_unresolved")),
        include_sources=bool(output_options.get("include_sources")),
        mode=mode,
        authorization_scope=authorization_scope,
        synthetic_fixture=fixture_requested,
    )
    return build_output(
        domain,
        mode,
        authorization_scope,
        findings,
        candidates,
        invalid_observations,
        source_status,
        fatal_errors,
        warnings,
        candidate_count=candidate_count,
        active_queries=active_queries,
        wildcard_detected=wildcard_detected,
        active_allowed=active_allowed,
        synthetic_fixture=fixture_requested,
        real_scan=False,
        planned_sources=planned_sources(passive_sources, active_options),
    )


def build_output(
    domain: str,
    mode: str,
    authorization_scope: str,
    findings: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    invalid_observations: list[dict[str, Any]],
    source_status: list[dict[str, Any]],
    fatal_errors: list[dict[str, Any]],
    warnings: list[str],
    *,
    candidate_count: int,
    active_queries: int,
    wildcard_detected: bool,
    active_allowed: bool,
    synthetic_fixture: bool,
    real_scan: bool,
    planned_sources: list[str],
) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "domain": domain,
        "mode": mode,
        "run_context": {
            "mode": mode,
            "input_target": domain,
            "authorization_scope": authorization_scope,
            "synthetic_fixture": synthetic_fixture,
            "real_scan": real_scan,
            "planned_sources": planned_sources,
        },
        "findings": findings,
        "candidates": candidates,
        "invalid_observations": invalid_observations,
        "source_status": source_status,
        "summary": {
            "confirmed_count": len(findings),
            "candidate_count": (
                candidate_count
                if mode == "dry_run"
                or any(item.get("status") == "dry_run" for item in source_status)
                else len(candidates)
            ),
            "invalid_count": len(invalid_observations),
            "candidate_observation_count": len(candidates),
            "invalid_observation_count": len(invalid_observations),
            "source_count": len(source_status),
            "domain": domain,
            "mode": mode,
            "target": domain,
            "authorization_scope": authorization_scope,
            "synthetic_fixture": synthetic_fixture,
            "real_scan": real_scan,
            "planned_sources": planned_sources,
            "generated_candidate_count": candidate_count,
            "finding_count": len(findings),
            "active_queries": active_queries,
            "wildcard_detected": wildcard_detected,
            "wildcard_filtered_count": sum(
                1
                for item in candidates + invalid_observations
                if item.get("status") == "wildcard_filtered"
            ),
            "errors": warnings[:MAX_ERRORS],
        },
        "errors": fatal_errors[:MAX_ERRORS],
        "safety": {
            "target_type_domain_only": True,
            "authorization_scope_required": True,
            "active_policy_allowed": active_allowed,
            "active_dns_queries": active_queries,
            "dictionary_candidates": candidate_count,
            "brute_force_attempts": 0,
            "port_scan_attempts": 0,
            "exploit_attempts": 0,
        },
    }


def canonical_mode(requested_mode: str, passive_options: dict[str, Any]) -> str:
    if requested_mode == "passive":
        sources = set(list_of_strings(passive_options.get("sources", [])))
        return "fixture" if sources == {"fixture"} else "passive_intel"
    if requested_mode == "active":
        return "active_dictionary"
    return requested_mode


def list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def planned_sources(passive_sources: list[str], active_options: dict[str, Any]) -> list[str]:
    sources: list[str] = []
    for source in passive_sources:
        if source == "fixture":
            sources.append("passive_fixture")
        elif source == "crtsh":
            sources.append("passive_crtsh")
        elif source in PASSIVE_INTEL_SOURCES:
            sources.append(f"passive_{source}")
    if bool(active_options.get("enabled")):
        sources.append("active_dictionary")
    return sorted(set(sources), key=lambda item: SOURCE_ORDER.get(item, 99))


def is_synthetic_domain(domain: str) -> bool:
    return domain in SYNTHETIC_DOMAINS or domain.endswith((".test", ".invalid", ".localhost"))


def fixture_domain_error(domain: str, fixture_file: str, mode: str) -> dict[str, Any] | None:
    try:
        path = resolve_plugin_file(fixture_file, "$.options.passive.fixture_file")
        with path.open("r", encoding="utf-8") as handle:
            fixture = json.load(handle)
        fixture_domain = validate_domain(str(fixture.get("domain", "")), "$.fixture.domain")
    except (InputError, OSError, json.JSONDecodeError) as error:
        return standard_error(
            "CONFIG_ERROR",
            f"fixture file could not be validated: {safe_message(error)}",
            field="$.options.passive.fixture_file",
            details={"input_target": domain, "fixture_file": fixture_file, "mode": mode},
        )
    if fixture_domain != domain:
        return standard_error(
            "CONFIG_ERROR",
            "fixture domain does not match input target; refusing to report synthetic example.com data as another target",
            field="$.options.passive.fixture_file",
            details={"input_target": domain, "fixture_domain": fixture_domain, "mode": mode},
        )
    return None


def run_passive(
    domain: str,
    options: dict[str, Any],
    results: dict[str, dict[str, Any]],
    source_status: list[dict[str, Any]],
    warnings: list[str],
) -> None:
    sources = options.get("sources", [])
    if "fixture" in sources:
        fixture_file = read_string(options, "fixture_file", "$.options.passive.fixture_file")
        before = len(results)
        try:
            load_passive_fixture(domain, fixture_file, results)
            source_status.append(
                source_state("fixture", True, "ok", len(results) - before, None)
            )
        except (InputError, OSError, json.JSONDecodeError) as error:
            source_status.append(
                source_state("fixture", True, "error", 0, safe_message(error))
            )
            raise
    if "crtsh" in sources:
        source_status.append(
            source_state(
                "crtsh",
                False,
                "skipped_p7_disabled",
                0,
                "crt.sh live queries are disabled in P5.6; use fixture/local cache input",
            )
        )

    cache_fields = {
        "local_cache": "local_cache_file",
        "passive_dns_cache": "passive_dns_cache_file",
    }
    for source, field in cache_fields.items():
        if source in sources:
            configured = options.get(field)
            if not isinstance(configured, str) or not configured:
                source_status.append(
                    source_state(
                        source,
                        True,
                        "skipped_not_configured",
                        0,
                        f"{field} is not configured",
                    )
                )
                continue
            try:
                count = load_passive_cache(domain, configured, source, results)
                source_status.append(
                    source_state(source, True, "ok" if count else "empty", count, None)
                )
            except (InputError, OSError, json.JSONDecodeError) as error:
                message = safe_message(error)
                warnings.append(f"{source} failed: {message}")
                source_status.append(source_state(source, True, "error", 0, message))

    secret_names = {
        "fofa": ("FOFA_EMAIL", "FOFA_KEY"),
        "shodan": ("SHODAN_API_KEY",),
        "censys": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
        "securitytrails": ("SECURITYTRAILS_API_KEY",),
        "virustotal": ("VIRUSTOTAL_API_KEY",),
    }
    for source, required_secrets in secret_names.items():
        if source not in sources:
            continue
        source_status.append(
            source_state(
                source,
                False,
                "skipped_p7_disabled",
                0,
                f"{source} live provider calls are disabled in P5.6; use fixture/local cache input",
            )
        )


def source_state(
    source: str,
    enabled: bool,
    status: str,
    result_count: int,
    error: str | None,
) -> dict[str, Any]:
    return {
        "type": "source_status",
        "source": source,
        "enabled": enabled,
        "status": status,
        "result_count": result_count,
        "error": error,
    }


def load_passive_cache(
    domain: str,
    cache_file: str,
    source: str,
    results: dict[str, dict[str, Any]],
) -> int:
    path = resolve_plugin_file(cache_file, f"$.options.passive.{source}_file")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload in ({}, [], None):
        return 0
    observations = payload.get("subdomains", []) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        raise InputError("passive cache must contain a subdomains array", f"$.options.passive.{source}_file")
    count = 0
    source_name = f"passive_{source}"
    for item in observations[:MAX_FINDINGS]:
        name = item.get("name") if isinstance(item, dict) else item
        if not isinstance(name, str) or not clean_subdomain(name, domain):
            continue
        confidence = 0.6
        if isinstance(item, dict) and isinstance(item.get("confidence"), (int, float)):
            confidence = min(max(float(item["confidence"]), 0.0), 1.0)
        add_observation(
            results,
            domain,
            name,
            source_name,
            confidence=confidence,
            records=[],
            raw={
                "source": source,
                "source_type": "passive_intel",
                "confidence": confidence,
            },
        )
        count += 1
    return count


def load_passive_fixture(
    domain: str,
    fixture_file: str,
    results: dict[str, dict[str, Any]],
) -> None:
    path = resolve_plugin_file(fixture_file, "$.options.passive.fixture_file")
    with path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)
    fixture_domain = validate_domain(str(fixture.get("domain", "")), "$.fixture.domain")
    if fixture_domain != domain:
        raise InputError("fixture domain does not match target domain", "$.fixture.domain")
    subdomains = fixture.get("subdomains")
    if not isinstance(subdomains, list):
        raise InputError("fixture.subdomains must be an array", "$.fixture.subdomains")
    for item in subdomains[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        confidence = float(item.get("confidence", 0.75))
        add_observation(
            results,
            domain,
            name,
            "passive_fixture",
            confidence=min(max(confidence, 0.0), 1.0),
            records=[],
            raw={
                "source": "fixture",
                "synthetic": True,
                "real_scan": False,
                "notice": "This run used local synthetic fixture data and does not represent live discovery against the target.",
            },
        )


def query_crtsh(domain: str, timeout: int) -> list[str]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={
            "Accept": "application/json",
            "User-Agent": "SentinelFlow-subdomain-discovery-plus/0.1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(1_000_000).decode("utf-8", errors="replace")
    if not body.strip():
        return []
    rows = json.loads(body)
    if not isinstance(rows, list):
        raise ValueError("crt.sh response was not a JSON array")
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            value = row.get(field)
            if not isinstance(value, str):
                continue
            for line in value.splitlines():
                cleaned = clean_subdomain(line, domain)
                if cleaned:
                    names.add(cleaned)
    return sorted(names)[:MAX_FINDINGS]


def run_active(
    domain: str,
    options: dict[str, Any],
    output_options: dict[str, Any],
    results: dict[str, dict[str, Any]],
    active_observations: list[dict[str, Any]],
    source_status: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    wordlist_file = read_string(options, "wordlist_file", "$.options.active.wordlist_file")
    max_candidates = bounded_int(options.get("max_candidates"), 100, 1, 10_000)
    candidates = load_wordlist(domain, wordlist_file, max_candidates)
    if bool(options.get("dry_run")):
        source_status.append(
            source_state(
                "active_dictionary",
                True,
                "dry_run",
                0,
                f"planned {len(candidates)} bounded dictionary candidates",
            )
        )
        return {
            "candidate_count": len(candidates),
            "active_queries": 0,
            "wildcard_detected": False,
        }

    resolvers = validate_resolvers(options.get("resolvers", []))
    record_types = validate_record_types(options.get("record_types", ["A", "AAAA"]))
    timeout = bounded_int(options.get("timeout_seconds"), 3, 1, 10)
    concurrency = bounded_int(options.get("concurrency"), 5, 1, 5)
    rate_limit = bounded_int(options.get("rate_limit_per_second"), 5, 1, 5)
    wildcard_detected = False
    wildcard_fingerprints: set[tuple[tuple[str, str], ...]] = set()
    active_queries = 0

    if bool(options.get("detect_wildcard")):
        wildcard_names = [
            f"sf-{secrets.token_hex(6)}-{index}.{domain}" for index in range(5)
        ]
        fingerprint_counts: dict[tuple[tuple[str, str], ...], int] = {}
        for name in wildcard_names:
            result = normalize_dns_result(
                resolve_candidate(name, record_types, resolvers, timeout)
            )
            active_queries += result["query_count"]
            records = result["records"]
            if records:
                fingerprint = record_fingerprint(records)
                fingerprint_counts[fingerprint] = fingerprint_counts.get(fingerprint, 0) + 1
        wildcard_fingerprints = {
            fingerprint for fingerprint, count in fingerprint_counts.items() if count >= 3
        }
        wildcard_detected = bool(wildcard_fingerprints)
        if wildcard_detected:
            warnings.append(
                "wildcard DNS detected from repeated random-name record fingerprints; matching dictionary results were filtered"
            )

    limiter = RateLimiter(rate_limit)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_name = {}
        for candidate in candidates:
            limiter.wait()
            future = executor.submit(
                resolve_candidate,
                candidate,
                record_types,
                resolvers,
                timeout,
            )
            future_to_name[future] = candidate
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = normalize_dns_result(future.result())
            except OSError as error:
                message = safe_message(error)
                warnings.append(f"DNS query warning for {name}: {message}")
                active_observations.append(
                    candidate_observation(
                        domain,
                        name,
                        "query_error",
                        records=[],
                        query_status="query_error",
                        detail=message,
                    )
                )
                continue
            active_queries += result["query_count"]
            records = result["records"]
            query_status = result.get("status", "ok" if records else "candidate_unresolved")
            fingerprint = record_fingerprint(records)
            wildcard_filtered = bool(records) and fingerprint in wildcard_fingerprints
            if wildcard_filtered:
                active_observations.append(
                    candidate_observation(
                        domain,
                        name,
                        "wildcard_filtered",
                        records=records,
                        query_status=query_status,
                        detail="DNS records matched the wildcard fingerprint.",
                    )
                )
                continue

            public_records = [
                enrich_record(record)
                for record in records
                if record.get("record_type") in {"A", "AAAA"}
                and is_public_routable_ip(record["value"])
            ]
            special_records = [
                enrich_record(record)
                for record in records
                if record.get("record_type") in {"A", "AAAA"}
                and not is_public_routable_ip(record["value"])
            ]
            if public_records:
                add_observation(
                    results,
                    domain,
                    name,
                    "active_dictionary",
                    confidence=0.68 if wildcard_detected else 0.78,
                    records=public_records,
                    raw={
                        "source": "active_dictionary",
                        "source_type": "active_verify",
                        "resolved": True,
                        "records": public_records,
                        "confidence": 0.68 if wildcard_detected else 0.78,
                        "wildcard_filtered": wildcard_filtered,
                        "query_status": query_status,
                    },
                )
                if special_records:
                    active_observations.append(
                        invalid_observation(
                            domain,
                            name,
                            "invalid_special_address",
                            special_records,
                            "DNS also returned non-public or special-use addresses.",
                        )
                    )
            elif special_records:
                active_observations.append(
                    invalid_observation(
                        domain,
                        name,
                        "invalid_special_address",
                        special_records,
                        "DNS result points only to non-public or special-use addresses.",
                    )
                )
            elif bool(output_options.get("include_unresolved")):
                status = (
                    query_status
                    if query_status in {"nxdomain", "timeout", "servfail", "query_error"}
                    else "candidate_unresolved"
                )
                active_observations.append(
                    candidate_observation(
                        domain,
                        name,
                        status,
                        records=[],
                        query_status=query_status,
                        detail="Generated from the bounded dictionary but DNS resolution was not confirmed.",
                    )
                )

    source_status.append(
        source_state(
            "active_dictionary",
            True,
            "ok",
            sum(
                1
                for entry in results.values()
                if "active_dictionary" in entry.get("sources", set())
            ),
            None,
        )
    )
    return {
        "candidate_count": len(candidates),
        "active_queries": active_queries,
        "wildcard_detected": wildcard_detected,
    }


def normalize_dns_result(result: dict[str, Any]) -> dict[str, Any]:
    records = result.get("records", [])
    return {
        "records": records if isinstance(records, list) else [],
        "query_count": int(result.get("query_count", 0)),
        "status": str(result.get("status", "ok" if records else "candidate_unresolved")),
    }


def record_fingerprint(records: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                str(record.get("record_type", "")),
                str(record.get("value", "")).lower().rstrip("."),
            )
            for record in records
            if record.get("record_type") and record.get("value")
        )
    )


def candidate_observation(
    domain: str,
    subdomain: str,
    status: str,
    *,
    records: list[dict[str, Any]],
    query_status: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "type": "subdomain_candidate",
        "status": status,
        "domain": domain,
        "subdomain": subdomain,
        "sources": ["active_dictionary"],
        "resolved": bool(records),
        "confirmed": False,
        "public_routable": False,
        "records": records,
        "confidence": 0.1 if status == "candidate_unresolved" else 0.0,
        "synthetic": False,
        "real_scan": True,
        "query_status": query_status,
        "evidence": {"summary": detail},
    }


def invalid_observation(
    domain: str,
    subdomain: str,
    status: str,
    records: list[dict[str, Any]],
    detail: str,
) -> dict[str, Any]:
    return {
        "type": "invalid_observation",
        "status": status,
        "domain": domain,
        "subdomain": subdomain,
        "records": records,
        "confidence": 0.0,
        "synthetic": False,
        "real_scan": True,
        "evidence": {"summary": detail},
    }


def enrich_record(record: dict[str, Any]) -> dict[str, Any]:
    value = str(record.get("value", ""))
    public = is_public_routable_ip(value)
    return {
        "record_type": str(record.get("record_type", "unknown")),
        "value": value,
        "address_class": address_class(value),
        "public_routable": public,
    }


def address_class(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "hostname" if DOMAIN_RE.fullmatch(value.rstrip(".")) else "invalid"
    if address in ipaddress.ip_network("198.18.0.0/15"):
        return "benchmark"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_reserved:
        return "reserved"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    return "public" if is_public_routable_ip(value) else "non_public"


def load_wordlist(domain: str, wordlist_file: str, max_candidates: int) -> list[str]:
    path = resolve_plugin_file(wordlist_file, "$.options.active.wordlist_file")
    candidates: dict[str, None] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            word = line.split("#", 1)[0].strip().lower().rstrip(".")
            if not word:
                continue
            if any(character in word for character in "/\\:@*;&|`$<>"):
                continue
            labels = word.split(".")
            if not all(LABEL_RE.fullmatch(label) for label in labels):
                continue
            if word.endswith(f".{domain}"):
                candidate = word
            else:
                candidate = f"{word}.{domain}"
            cleaned = clean_subdomain(candidate, domain)
            if cleaned:
                candidates.setdefault(cleaned, None)
            if len(candidates) >= max_candidates:
                break
    return sorted(candidates)


def resolve_candidate(
    hostname: str,
    record_types: list[str],
    resolvers: list[str],
    timeout: int,
) -> dict[str, Any]:
    records: dict[tuple[str, str], dict[str, str]] = {}
    query_count = 0
    statuses: list[str] = []
    if resolvers == ["system"]:
        for record_type in record_types:
            values, status = resolve_system(hostname, record_type)
            statuses.append(status)
            for address in values:
                records[(record_type, address)] = {
                    "record_type": record_type,
                    "value": address,
                }
            query_count += 1
        return {
            "records": list(records.values()),
            "query_count": query_count,
            "status": aggregate_query_status(statuses, bool(records)),
        }

    for record_type in record_types:
        for resolver in resolvers:
            query_count += 1
            values, status = udp_dns_query(hostname, record_type, resolver, timeout)
            statuses.append(status)
            for address in values:
                records[(record_type, address)] = {
                    "record_type": record_type,
                    "value": address,
                }
            if any(key[0] == record_type for key in records):
                break
    return {
        "records": sorted(
            records.values(), key=lambda item: (item["record_type"], item["value"])
        ),
        "query_count": query_count,
        "status": aggregate_query_status(statuses, bool(records)),
    }


def aggregate_query_status(statuses: list[str], has_records: bool) -> str:
    if has_records:
        return "ok"
    for status in ("servfail", "timeout", "query_error", "nxdomain", "empty"):
        if status in statuses:
            return status
    return "candidate_unresolved"


def resolve_system(hostname: str, record_type: str) -> tuple[list[str], str]:
    if record_type == "CNAME":
        return [], "skipped_unsupported"
    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    addresses: set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
    except socket.gaierror as error:
        return [], "nxdomain" if error.errno == socket.EAI_NONAME else "query_error"
    for info in infos:
        address = info[4][0]
        addresses.add(address)
    return sorted(addresses), "ok" if addresses else "empty"


def udp_dns_query(
    hostname: str,
    record_type: str,
    resolver: str,
    timeout: int,
) -> tuple[list[str], str]:
    query_id = random.SystemRandom().randint(0, 65535)
    qtype = QTYPE[record_type]
    packet = build_dns_query(query_id, hostname, qtype)
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (resolver, 53))
            response, _ = sock.recvfrom(4096)
        except socket.timeout:
            return [], "timeout"
        except OSError:
            return [], "query_error"
    return parse_dns_response(response, query_id, qtype)


def build_dns_query(query_id: int, hostname: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in hostname.split(".")
    )
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def parse_dns_response(
    response: bytes,
    query_id: int,
    qtype: int,
) -> tuple[list[str], str]:
    if len(response) < 12:
        return [], "query_error"
    (
        response_id,
        flags,
        qdcount,
        ancount,
        _nscount,
        _arcount,
    ) = struct.unpack("!HHHHHH", response[:12])
    rcode = flags & 0x000F
    if response_id != query_id:
        return [], "query_error"
    if rcode == 3:
        return [], "nxdomain"
    if rcode == 2:
        return [], "servfail"
    if rcode != 0:
        return [], "query_error"
    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(response, offset)
        offset += 4
        if offset > len(response):
            return [], "query_error"
    values: set[str] = set()
    for _ in range(ancount):
        offset = skip_dns_name(response, offset)
        if offset + 10 > len(response):
            return [], "query_error"
        record_type, record_class, _ttl, rdlength = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if record_class != 1 or record_type != qtype:
            continue
        if record_type == 1 and len(rdata) == 4:
            values.add(socket.inet_ntop(socket.AF_INET, rdata))
        elif record_type == 28 and len(rdata) == 16:
            values.add(socket.inet_ntop(socket.AF_INET6, rdata))
        elif record_type == 5:
            cname, _ = decode_dns_name(response, offset - rdlength)
            if cname:
                values.add(cname.rstrip(".").lower())
    return sorted(values), "ok" if values else "empty"


def decode_dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    consumed = offset
    jumped = False
    seen: set[int] = set()
    while offset < len(message):
        if offset in seen:
            return "", consumed
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                return "", consumed
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                consumed = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                consumed = offset + 1
            return ".".join(labels), consumed
        offset += 1
        if offset + length > len(message):
            return "", consumed
        labels.append(message[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
        if not jumped:
            consumed = offset
    return "", consumed


def skip_dns_name(message: bytes, offset: int) -> int:
    while offset < len(message):
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length
    return len(message)


def add_observation(
    results: dict[str, dict[str, Any]],
    domain: str,
    subdomain: str,
    source: str,
    confidence: float,
    records: list[dict[str, str]],
    raw: dict[str, Any],
) -> None:
    cleaned = clean_subdomain(subdomain, domain)
    if not cleaned:
        return
    entry = results.setdefault(
        cleaned,
        {
            "domain": domain,
            "subdomain": cleaned,
            "sources": set(),
            "records": {},
            "confidence": 0.0,
            "raw": [],
        },
    )
    entry["sources"].add(source)
    for record in records:
        record_type = record.get("record_type")
        value = record.get("value")
        if record_type in {"A", "AAAA", "CNAME"} and isinstance(value, str):
            entry["records"][(record_type, value)] = {
                "record_type": record_type,
                "value": value,
            }
    entry["confidence"] = max(float(entry["confidence"]), confidence)
    if len(entry["raw"]) < 8:
        entry["raw"].append(raw)


def classify_observations(
    domain: str,
    results: dict[str, dict[str, Any]],
    active_observations: list[dict[str, Any]],
    include_unresolved: bool,
    include_sources: bool,
    mode: str,
    authorization_scope: str,
    synthetic_fixture: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    invalid_observations: list[dict[str, Any]] = []
    for subdomain in sorted(results):
        entry = results[subdomain]
        sources = sorted(entry["sources"], key=lambda item: SOURCE_ORDER.get(item, 99))
        records = sorted(
            entry["records"].values(), key=lambda item: (item["record_type"], item["value"])
        )
        source_set = set(sources)
        public_records = [record for record in records if is_public_routable_ip(record["value"])]
        special_records = [record for record in records if record not in public_records]
        trusted_passive = bool(
            source_set
            & {
                "passive_crtsh",
                "passive_fofa",
                "passive_shodan",
                "passive_censys",
                "passive_securitytrails",
                "passive_virustotal",
            }
        )
        multi_source = len(sources) > 1
        confirmed = synthetic_fixture or trusted_passive or multi_source or bool(public_records)
        addresses = sorted({record["value"] for record in records})[:MAX_RECORDS_PER_NAME]
        primary_record_type = "unknown"
        if any(record["record_type"] == "A" for record in records):
            primary_record_type = "A"
        elif any(record["record_type"] == "AAAA" for record in records):
            primary_record_type = "AAAA"
        confidence = (
            min(max(float(entry["confidence"]), 0.8) + 0.05 * (len(sources) - 1), 0.95)
            if confirmed
            else min(float(entry["confidence"]), 0.45)
        )
        summary = evidence_summary(subdomain, sources, records)
        source_details = source_details_for(entry, sources)
        common = {
            "domain": domain,
            "subdomain": subdomain,
            "source": sources[0] if len(sources) == 1 else "merged",
            "sources": sources if include_sources else sources[:1],
            "resolved": bool(records),
            "confirmed": confirmed,
            "record_type": primary_record_type,
            "addresses": addresses,
            "records": [enrich_record(record) for record in records[:MAX_RECORDS_PER_NAME]],
            "confidence": round(confidence, 3),
            "public_routable": bool(public_records),
            "synthetic": synthetic_fixture,
            "real_scan": not synthetic_fixture,
            "evidence": {
                "summary": fixture_notice(summary) if synthetic_fixture else summary,
                "items": [],
            },
            "source_details": source_details,
        }
        if not confirmed:
            if include_unresolved:
                candidates.append(
                    {
                        **common,
                        "type": "subdomain_candidate",
                        "confirmed": False,
                        "status": "candidate_unconfirmed",
                    }
                )
            continue

        finding = {
            **common,
            "type": "subdomain_result",
            "confirmed": True,
            "status": "confirmed",
            "raw": {
                "retained": True,
                "policy": "non-sensitive-subdomain-metadata-only",
                "observations": entry["raw"],
                "run_context": {
                    "mode": mode,
                    "input_target": domain,
                    "authorization_scope": authorization_scope,
                    "synthetic_fixture": synthetic_fixture,
                    "real_scan": not synthetic_fixture,
                },
                "source_details": source_details,
                "status": "confirmed",
                "confirmed": True,
                "public_routable_records": public_records,
                "special_records": special_records,
                "x-sentinelflow-fixture.synthetic": synthetic_fixture,
                "x-sentinelflow-fixture.source": "local_fixture" if synthetic_fixture else None,
                "x-sentinelflow-fixture.real_scan": not synthetic_fixture,
            },
            "synthetic_fixture": synthetic_fixture,
        }
        findings.append(finding)
        if len(findings) >= MAX_FINDINGS:
            break

    for observation in active_observations:
        if observation.get("type") == "invalid_observation":
            invalid_observations.append(observation)
        elif include_unresolved:
            candidates.append(observation)
    return findings, candidates[:MAX_FINDINGS], invalid_observations[:MAX_FINDINGS]


def source_details_for(
    entry: dict[str, Any],
    sources: list[str],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    raw_observations = entry.get("raw", [])
    for source in sources:
        matching = next(
            (
                item
                for item in raw_observations
                if isinstance(item, dict)
                and (
                    item.get("source") == source
                    or f"passive_{item.get('source')}" == source
                )
            ),
            {},
        )
        details.append(
            {
                "source": source,
                "source_type": (
                    "fixture"
                    if source == "passive_fixture"
                    else "active_verify"
                    if source == "active_dictionary"
                    else "passive_intel"
                ),
                "resolved": bool(matching.get("resolved", False)),
                "records": matching.get("records", []),
                "confidence": float(
                    matching.get("confidence", entry.get("confidence", 0.0))
                ),
            }
        )
    return details


def fixture_notice(summary: str) -> str:
    return (
        f"{summary} This run used local synthetic fixture data and does not "
        "represent live discovery against the target."
    )


def evidence_summary(
    subdomain: str,
    sources: list[str],
    records: list[dict[str, str]],
) -> str:
    source_label = ", ".join(sources)
    if records:
        types = sorted({record["record_type"] for record in records})
        return (
            f"{subdomain} discovered by {source_label} and resolved with "
            f"{'/'.join(types)} DNS record data."
        )
    return f"{subdomain} discovered by {source_label}; DNS resolution was not confirmed."


def clean_subdomain(value: str, domain: str) -> str | None:
    name = value.strip().lower().rstrip(".")
    while name.startswith("*."):
        name = name[2:]
    if name == domain or not name.endswith(f".{domain}"):
        return None
    if not DOMAIN_RE.fullmatch(name):
        return None
    return name


def validate_domain(value: str, field: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if (
        not domain
        or domain.startswith("*.")
        or "://" in domain
        or "/" in domain
        or any(character in domain for character in "\\:@*;&|`$<> \t\r\n")
    ):
        raise InputError("target value must be a plain authorized domain", field)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise InputError("IP addresses are not valid subdomain discovery targets", field)
    if not DOMAIN_RE.fullmatch(domain):
        raise InputError("target value must be a valid domain name", field)
    return domain


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


def validate_resolvers(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise InputError("active.resolvers must be a non-empty array", "$.options.active.resolvers")
    resolvers: list[str] = []
    for index, resolver in enumerate(value):
        if resolver == "system":
            resolvers.append(resolver)
            continue
        if not isinstance(resolver, str):
            raise InputError("resolver must be a string", f"$.options.active.resolvers[{index}]")
        try:
            ipaddress.ip_address(resolver)
        except ValueError as error:
            raise InputError(
                "resolver must be system or an IP address",
                f"$.options.active.resolvers[{index}]",
            ) from error
        resolvers.append(resolver)
    if "system" in resolvers and len(resolvers) > 1:
        raise InputError(
            "system resolver cannot be combined with explicit resolvers",
            "$.options.active.resolvers",
        )
    return resolvers


def validate_record_types(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise InputError(
            "active.record_types must be a non-empty array",
            "$.options.active.record_types",
        )
    record_types = []
    for item in value:
        if item not in {"A", "AAAA"}:
            raise InputError(
                "record type must be A or AAAA",
                "$.options.active.record_types",
            )
        if item not in record_types:
            record_types.append(item)
    return record_types


def resolve_plugin_file(value: str, field: str) -> Path:
    if "\x00" in value:
        raise InputError("file path contains a NUL byte", field)
    path = Path(value)
    if path.is_absolute():
        candidate = path
    else:
        candidate = PLUGIN_ROOT / path
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise InputError("file path does not exist", field) from error
    try:
        resolved.relative_to(PLUGIN_ROOT)
    except ValueError as error:
        raise InputError("file path must stay inside the plugin directory", field) from error
    if not resolved.is_file():
        raise InputError("file path must point to a regular file", field)
    return resolved


def read_object(value: dict[str, Any], key: str, field: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise InputError(f"{key} must be an object", field)
    return item


def read_string(value: dict[str, Any], key: str, field: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise InputError(f"{key} must be a non-empty string", field)
    return item


def read_path(value: dict[str, Any], path: list[str], expected_type: type) -> Any:
    current: Any = value
    for item in path:
        if not isinstance(current, dict) or item not in current:
            raise InputError("required field is missing", "$." + ".".join(path))
        current = current[item]
    if not isinstance(current, expected_type):
        raise InputError("field has the wrong type", "$." + ".".join(path))
    return current


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or value < minimum or value > maximum:
        return default
    return value


def standard_error(
    code: str,
    message: str,
    *,
    field: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "details": details or {},
    }
    if field:
        error["field"] = field
    return error


def safe_message(error: BaseException) -> str:
    return str(error).replace("\n", " ").strip()[:512] or error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(main())
