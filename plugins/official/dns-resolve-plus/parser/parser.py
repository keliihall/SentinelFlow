#!/usr/bin/env python3
"""Parser contract helper for dns-resolve-plus runner output."""

from __future__ import annotations

import json
import sys
from typing import Any


def parse(raw: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for item in raw.get("results", []):
        if not isinstance(item, dict) or item.get("type") != "dns_result":
            continue
        if not item.get("resolved", False):
            continue
        record_type = str(item.get("record_type", ""))
        if record_type in {"A", "AAAA"} and not item.get("valid_for_port_probe", False):
            continue
        domain = str(item.get("domain", ""))
        value = item.get("value")
        confidence = item.get("confidence", 0)
        summary = (
            item.get("evidence", {}).get("summary")
            if isinstance(item.get("evidence"), dict)
            else None
        ) or f"{record_type} record for {domain} observed."
        findings.append(
            {
                "title": "DNS resolution observed",
                "severity": "info",
                "summary": summary,
                "evidence": [
                    {
                        "evidenceType": "dns-resolution",
                        "description": "Structured DNS resolution evidence.",
                        "data": {
                            "findingType": "asset.dns_resolve",
                            "target": {"type": "domain", "value": domain},
                            "confidence": confidence,
                            "x-sentinelflow-dns.domain": domain,
                            "x-sentinelflow-dns.record_type": record_type,
                            "x-sentinelflow-dns.value": value,
                            "x-sentinelflow-dns.sources": item.get("sources", []),
                            "x-sentinelflow-dns.source_details": item.get("source_details", []),
                            "x-sentinelflow-dns.source_count": item.get("source_count", 0),
                            "x-sentinelflow-dns.source_agreement": item.get("source_agreement", "unknown"),
                            "x-sentinelflow-dns.conflict": item.get("conflict", False),
                            "x-sentinelflow-dns.conflict_reason": item.get("conflict_reason"),
                            "x-sentinelflow-dns.observed_at": item.get("observed_at"),
                            "x-sentinelflow-dns.stale": item.get("stale", False),
                            "x-sentinelflow-dns.resolved": item.get("resolved", False),
                            "x-sentinelflow-dns.status": item.get("status", "resolved"),
                            "x-sentinelflow-dns.address_class": item.get("address_class", "not_applicable"),
                            "x-sentinelflow-dns.public_routable": item.get("public_routable", False),
                            "x-sentinelflow-dns.valid_for_port_probe": item.get("valid_for_port_probe", False),
                            "x-sentinelflow-dns.confidence_strategy": item.get("confidence_strategy"),
                        },
                    }
                ],
            }
        )
    return {"values": raw, "findings": findings, "errors": parser_errors(raw)}


def parser_errors(raw: dict[str, Any]) -> list[dict[str, Any]]:
    errors = []
    for error in raw.get("errors", []):
        if not isinstance(error, dict):
            continue
        errors.append(
            {
                "code": str(error.get("code", "ParserInputError")),
                "message": str(error.get("message", "parser input error")),
                "details": dict(error.get("details", {})),
                **({"field": error["field"]} if isinstance(error.get("field"), str) else {}),
            }
        )
    return errors


def main() -> int:
    raw = json.load(sys.stdin)
    if not isinstance(raw, dict):
        print("raw parser input must be a JSON object", file=sys.stderr)
        return 2
    json.dump(parse(raw), sys.stdout, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
