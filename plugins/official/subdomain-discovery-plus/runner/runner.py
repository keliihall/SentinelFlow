#!/usr/bin/env python3
"""Bounded passive and active subdomain discovery runner for SentinelFlow."""

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
PASSIVE_INTEL_SOURCES = {"crtsh", "local_cache", "passive_dns_cache", "fofa", "shodan"}
SYNTHETIC_SCOPE = "fixture:local-only"
SYNTHETIC_DOMAINS = {"example.com", "example.org"}
QTYPE = {"A": 1, "AAAA": 28}


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
        run_passive(domain, passive_options, results, warnings)

    if active_requested and not active_allowed:
        fatal_errors.append(
            standard_error(
                "PolicyDenied",
                "active DNS dictionary discovery requires policy.allow_active_verify=true",
                field="$.policy.allow_active_verify",
                details={"mode": mode, "activeEnabled": True},
            )
        )
    elif active_requested:
        active_result = run_active(domain, active_options, output_options, results, warnings)
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

    findings = finalize_findings(
        domain,
        results,
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
        fatal_errors,
        warnings,
        candidate_count=candidate_count,
        active_queries=active_queries,
        wildcard_detected=wildcard_detected,
        active_allowed=active_allowed,
        synthetic_fixture=fixture_requested,
        real_scan=not fixture_requested,
        planned_sources=planned_sources(passive_sources, active_options),
    )


def build_output(
    domain: str,
    mode: str,
    authorization_scope: str,
    findings: list[dict[str, Any]],
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
        "summary": {
            "confirmed_count": sum(
                1 for item in findings if item.get("type") == "subdomain_finding"
            ),
            "candidate_observation_count": sum(
                1 for item in findings if item.get("type") == "subdomain_candidate"
            ),
            "invalid_observation_count": sum(
                1
                for item in findings
                if item.get("status") == "invalid_special_address"
            ),
            "domain": domain,
            "mode": mode,
            "target": domain,
            "authorization_scope": authorization_scope,
            "synthetic_fixture": synthetic_fixture,
            "real_scan": real_scan,
            "planned_sources": planned_sources,
            "candidate_count": candidate_count,
            "finding_count": sum(
                1 for item in findings if item.get("type") == "subdomain_finding"
            ),
            "active_queries": active_queries,
            "wildcard_detected": wildcard_detected,
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
    warnings: list[str],
) -> None:
    sources = options.get("sources", [])
    if "fixture" in sources:
        fixture_file = read_string(options, "fixture_file", "$.options.passive.fixture_file")
        load_passive_fixture(domain, fixture_file, results)
    if "crtsh" in sources and bool(options.get("crtsh_enabled")):
        timeout = bounded_int(options.get("crtsh_timeout_seconds"), 10, 1, 30)
        try:
            for name in query_crtsh(domain, timeout):
                add_observation(
                    results,
                    domain,
                    name,
                    "passive_crtsh",
                    confidence=0.65,
                    records=[],
                    raw={"provider": "crtsh"},
                )
        except (OSError, urllib.error.URLError, TimeoutError, ValueError) as error:
            warnings.append(f"crt.sh query failed: {safe_message(error)}")
    for source in ("local_cache", "passive_dns_cache", "fofa", "shodan"):
        if source in sources:
            warnings.append(f"{source} skipped: provider is not configured in this plugin build")


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
    warnings: list[str],
) -> dict[str, Any]:
    wordlist_file = read_string(options, "wordlist_file", "$.options.active.wordlist_file")
    max_candidates = bounded_int(options.get("max_candidates"), 100, 1, 10_000)
    candidates = load_wordlist(domain, wordlist_file, max_candidates)
    if bool(options.get("dry_run")):
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
    wildcard_addresses: set[str] = set()
    active_queries = 0

    if bool(options.get("detect_wildcard")):
        wildcard_names = [
            f"sf-{secrets.token_hex(6)}-{index}.{domain}" for index in range(3)
        ]
        wildcard_hits = 0
        for name in wildcard_names:
            result = resolve_candidate(name, record_types, resolvers, timeout)
            active_queries += result["query_count"]
            records = result["records"]
            if records:
                wildcard_hits += 1
                wildcard_addresses.update(record["value"] for record in records)
        wildcard_detected = wildcard_hits >= 2
        if wildcard_detected:
            warnings.append(
                "wildcard DNS detected; active records matching wildcard addresses were filtered"
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
                result = future.result()
            except OSError as error:
                warnings.append(f"DNS query warning for {name}: {safe_message(error)}")
                continue
            active_queries += result["query_count"]
            records = result["records"]
            wildcard_filtered = False
            if wildcard_detected:
                filtered = [
                    record for record in records if record["value"] not in wildcard_addresses
                ]
                wildcard_filtered = len(filtered) != len(records)
                records = filtered
                existing_sources = results.get(name, {}).get("sources", set())
                if records and not (existing_sources - {"active_dictionary"}):
                    records = []
                    wildcard_filtered = True
            if records:
                add_observation(
                    results,
                    domain,
                    name,
                    "active_dictionary",
                    confidence=0.65 if wildcard_detected else 0.85,
                    records=records,
                    raw={
                        "source": "active_dictionary",
                        "wildcard_filtered": wildcard_filtered,
                    },
                )
            elif bool(output_options.get("include_unresolved")):
                add_observation(
                    results,
                    domain,
                    name,
                    "active_dictionary",
                    confidence=0.10,
                    records=[],
                    raw={
                        "source": "active_dictionary",
                        "resolved": False,
                        "status": "candidate",
                    },
                )

    return {
        "candidate_count": len(candidates),
        "active_queries": active_queries,
        "wildcard_detected": wildcard_detected,
    }


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
    if resolvers == ["system"]:
        for record_type in record_types:
            for address in resolve_system(hostname, record_type):
                records[(record_type, address)] = {
                    "record_type": record_type,
                    "value": address,
                }
            query_count += 1
        return {"records": list(records.values()), "query_count": query_count}

    for record_type in record_types:
        for resolver in resolvers:
            query_count += 1
            for address in udp_dns_query(hostname, record_type, resolver, timeout):
                records[(record_type, address)] = {
                    "record_type": record_type,
                    "value": address,
                }
            if any(key[0] == record_type for key in records):
                break
    return {"records": sorted(records.values(), key=lambda item: (item["record_type"], item["value"])), "query_count": query_count}


def resolve_system(hostname: str, record_type: str) -> list[str]:
    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    addresses: set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    for info in infos:
        address = info[4][0]
        addresses.add(address)
    return sorted(addresses)


def udp_dns_query(hostname: str, record_type: str, resolver: str, timeout: int) -> list[str]:
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
            return []
    return parse_dns_response(response, query_id, qtype)


def build_dns_query(query_id: int, hostname: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in hostname.split(".")
    )
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def parse_dns_response(response: bytes, query_id: int, qtype: int) -> list[str]:
    if len(response) < 12:
        return []
    (
        response_id,
        flags,
        qdcount,
        ancount,
        _nscount,
        _arcount,
    ) = struct.unpack("!HHHHHH", response[:12])
    if response_id != query_id or flags & 0x000F != 0:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(response, offset)
        offset += 4
        if offset > len(response):
            return []
    addresses: set[str] = set()
    for _ in range(ancount):
        offset = skip_dns_name(response, offset)
        if offset + 10 > len(response):
            return []
        record_type, record_class, _ttl, rdlength = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if record_class != 1 or record_type != qtype:
            continue
        if record_type == 1 and len(rdata) == 4:
            addresses.add(socket.inet_ntop(socket.AF_INET, rdata))
        elif record_type == 28 and len(rdata) == 16:
            addresses.add(socket.inet_ntop(socket.AF_INET6, rdata))
    return sorted(addresses)


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
        if record_type in {"A", "AAAA"} and isinstance(value, str):
            entry["records"][(record_type, value)] = {
                "record_type": record_type,
                "value": value,
            }
    entry["confidence"] = max(float(entry["confidence"]), confidence)
    if len(entry["raw"]) < 8:
        entry["raw"].append(raw)


def finalize_findings(
    domain: str,
    results: dict[str, dict[str, Any]],
    include_unresolved: bool,
    include_sources: bool,
    mode: str,
    authorization_scope: str,
    synthetic_fixture: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for subdomain in sorted(results):
        entry = results[subdomain]
        sources = sorted(entry["sources"], key=lambda item: SOURCE_ORDER.get(item, 99))
        records = sorted(
            entry["records"].values(), key=lambda item: (item["record_type"], item["value"])
        )
        active_only = sources == ["active_dictionary"]
        source_set = set(sources)
        public_records = [record for record in records if is_public_routable_ip(record["value"])]
        special_records = [record for record in records if record not in public_records]
        trusted_passive = bool(source_set & {"passive_crtsh", "passive_local_cache", "passive_dns_cache", "passive_fofa", "passive_shodan"})
        multi_source = len(sources) > 1
        confirmed = (
            synthetic_fixture
            or trusted_passive
            or multi_source
            or bool(public_records)
        )
        invalid_special = bool(records) and not public_records and active_only
        if active_only and not records and not include_unresolved:
            continue
        addresses = sorted({record["value"] for record in records})[:MAX_RECORDS_PER_NAME]
        primary_record_type = "unknown"
        if any(record["record_type"] == "A" for record in records):
            primary_record_type = "A"
        elif any(record["record_type"] == "AAAA" for record in records):
            primary_record_type = "AAAA"
        if not confirmed:
            if invalid_special:
                confidence = 0.0
            elif active_only and not records:
                confidence = min(float(entry["confidence"]), 0.15)
            else:
                confidence = min(float(entry["confidence"]), 0.3)
        else:
            confidence = min(float(entry["confidence"]) + 0.05 * (len(sources) - 1), 0.95)
        summary = evidence_summary(subdomain, sources, records)
        status = "confirmed" if confirmed else ("invalid_special_address" if invalid_special else "candidate")
        finding = {
            "type": "subdomain_finding" if confirmed else "subdomain_candidate",
            "domain": domain,
            "subdomain": subdomain,
            "source": sources[0] if len(sources) == 1 else "merged",
            "sources": sources if include_sources else sources[:1],
            "resolved": bool(records),
            "confirmed": confirmed,
            "status": status,
            "record_type": primary_record_type,
            "addresses": addresses,
            "records": records[:MAX_RECORDS_PER_NAME],
            "confidence": round(confidence, 3),
            "evidence": {
                "summary": fixture_notice(summary) if synthetic_fixture else summary,
                "items": [],
            },
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
                "source_details": [
                    {
                        "source": source,
                        "type": "fixture" if source == "passive_fixture" else "passive_or_active",
                    }
                    for source in sources
                ],
                "status": status,
                "confirmed": confirmed,
                "public_routable_records": public_records,
                "special_records": special_records,
                "x-sentinelflow-fixture.synthetic": synthetic_fixture,
                "x-sentinelflow-fixture.source": "local_fixture" if synthetic_fixture else None,
                "x-sentinelflow-fixture.real_scan": not synthetic_fixture,
            },
            "source_details": [
                {
                    "source": source,
                    "type": "fixture" if source == "passive_fixture" else "passive_or_active",
                }
                for source in sources
            ],
            "synthetic_fixture": synthetic_fixture,
            "real_scan": not synthetic_fixture,
        }
        findings.append(finding)
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


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
