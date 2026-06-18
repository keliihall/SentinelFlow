#!/usr/bin/env python3
"""Passive public-source subdomain discovery runner for SentinelFlow."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any


PROVIDERS = {"crtsh", "hackertarget", "buffer_over"}
DOMAIN_RE = re.compile(
    r"^(?=.{3,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
MAX_RECORDS = 10_000

FIXTURE_RECORDS = {
    "crtsh": ["www.example.com", "mail.example.com"],
    "hackertarget": ["www.example.com", "api.example.com"],
    "buffer_over": ["mail.example.com", "docs.example.com"],
}


class InputError(Exception):
    """Controlled input validation error."""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        spec = read_spec(payload)
        root_domain = normalize_domain(spec["root_domain"])
        providers = spec["providers"]
        timeout = int(spec["timeout"])
    except (json.JSONDecodeError, InputError, KeyError, TypeError, ValueError) as error:
        print(f"invalid input: {error}", file=sys.stderr)
        return 2

    provider_results = []
    discovered: dict[str, set[str]] = defaultdict(set)
    for provider in providers:
        result = query_provider(provider, root_domain, timeout)
        provider_results.append(result)
        for name in result["names"]:
            discovered[name].add(provider)

    records = [
        {
            "name": name,
            "root_domain": root_domain,
            "sources": sorted(discovered[name]),
        }
        for name in sorted(discovered)
    ][:MAX_RECORDS]

    output = {
        "source": "passive-subdomain-discovery",
        "root_domain": root_domain,
        "providers": [strip_internal_fields(result) for result in provider_results],
        "records": records,
        "summary": {
            "total_subdomains": len(records),
            "provider_count": len(providers),
        },
        "safety": {
            "passive_only": True,
            "active_dns_queries": 0,
            "brute_force_attempts": 0,
            "dictionary_candidates": 0,
            "port_scan_attempts": 0,
            "exploit_attempts": 0,
        },
    }
    json.dump(output, sys.stdout, separators=(",", ":"))
    return 0


def read_spec(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("spec"), dict):
        raise InputError("payload must contain object field spec")
    spec = payload["spec"]
    root_domain = spec.get("root_domain")
    providers = spec.get("providers")
    timeout = spec.get("timeout")
    if not isinstance(root_domain, str) or not DOMAIN_RE.fullmatch(root_domain):
        raise InputError("spec.root_domain must be a valid domain name")
    if (
        not isinstance(providers, list)
        or not providers
        or len(providers) > 3
        or len(set(providers)) != len(providers)
        or any(provider not in PROVIDERS for provider in providers)
    ):
        raise InputError("spec.providers must contain unique supported providers")
    if not isinstance(timeout, int) or timeout < 1 or timeout > 30:
        raise InputError("spec.timeout must be an integer from 1 through 30")
    return spec


def normalize_domain(value: str) -> str:
    return value.rstrip(".").lower()


def query_provider(provider: str, root_domain: str, timeout: int) -> dict[str, Any]:
    if root_domain == "example.com":
        names = filter_subdomains(FIXTURE_RECORDS[provider], root_domain)
        return {
            "name": provider,
            "status": "succeeded",
            "source_type": "embedded-fixture",
            "record_count": len(names),
            "names": names,
        }
    try:
        if provider == "crtsh":
            names = query_crtsh(root_domain, timeout)
        elif provider == "hackertarget":
            names = query_hackertarget(root_domain, timeout)
        elif provider == "buffer_over":
            names = query_buffer_over(root_domain, timeout)
        else:
            raise InputError("unsupported provider")
        names = filter_subdomains(names, root_domain)
        return {
            "name": provider,
            "status": "succeeded",
            "source_type": "public-http",
            "record_count": len(names),
            "names": names,
        }
    except (InputError, urllib.error.URLError, TimeoutError, ValueError) as error:
        return {
            "name": provider,
            "status": "failed",
            "source_type": "public-http",
            "record_count": 0,
            "error": safe_error(error),
            "names": [],
        }


def query_crtsh(root_domain: str, timeout: int) -> list[str]:
    query = urllib.parse.urlencode({"q": f"%.{root_domain}", "output": "json"})
    body = http_get(f"https://crt.sh/?{query}", timeout)
    if not body.strip():
        return []
    rows = json.loads(body)
    if not isinstance(rows, list):
        raise ValueError("crtsh response was not a JSON array")
    names = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            value = row.get(field)
            if isinstance(value, str):
                names.extend(value.splitlines())
    return names


def query_hackertarget(root_domain: str, timeout: int) -> list[str]:
    query = urllib.parse.urlencode({"q": root_domain})
    body = http_get(f"https://api.hackertarget.com/hostsearch/?{query}", timeout)
    names = []
    for line in body.splitlines():
        hostname = line.split(",", 1)[0].strip()
        if hostname and "error" not in hostname.lower():
            names.append(hostname)
    return names


def query_buffer_over(root_domain: str, timeout: int) -> list[str]:
    query = urllib.parse.urlencode({"q": f".{root_domain}"})
    body = http_get(f"https://dns.bufferover.run/dns?{query}", timeout)
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("buffer_over response was not a JSON object")
    names = []
    for field in ("FDNS_A", "RDNS"):
        values = data.get(field, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            names.append(value.rsplit(",", 1)[-1].strip())
    return names


def http_get(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json,text/plain;q=0.8",
            "User-Agent": "SentinelFlow-subdomain-discovery/0.1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=min(timeout, 10)) as response:
        return response.read(1_000_000).decode("utf-8", errors="replace")


def filter_subdomains(names: list[str], root_domain: str) -> list[str]:
    suffix = f".{root_domain}"
    filtered = set()
    for candidate in names:
        name = normalize_domain(candidate.strip().lstrip("*."))
        if name != root_domain and name.endswith(suffix) and DOMAIN_RE.fullmatch(name):
            filtered.add(name)
    return sorted(filtered)[:MAX_RECORDS]


def strip_internal_fields(result: dict[str, Any]) -> dict[str, Any]:
    public = {
        "name": result["name"],
        "status": result["status"],
        "source_type": result["source_type"],
        "record_count": result["record_count"],
    }
    if "error" in result:
        public["error"] = result["error"]
    return public


def safe_error(error: Exception) -> str:
    message = str(error).replace("\n", " ").strip()
    return message[:512] or error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(main())

