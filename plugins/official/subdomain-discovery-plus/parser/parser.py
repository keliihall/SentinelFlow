#!/usr/bin/env python3
"""Parser contract helper for subdomain-discovery-plus runner output.

The current v1alpha1 Manifest only allows trusted built-in parsers during normal
SentinelFlow execution. This file mirrors the built-in parser behavior for
plugin-local tests and documentation.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def parse(raw: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for item in raw.get("findings", []):
        if not isinstance(item, dict) or item.get("type") != "subdomain_finding":
            continue
        domain = str(item.get("domain", ""))
        subdomain = str(item.get("subdomain", ""))
        sources = list(item.get("sources", []))
        resolved = bool(item.get("resolved", False))
        records = list(item.get("records", []))
        addresses = list(item.get("addresses", []))
        confidence = item.get("confidence", 0)
        source_details = item.get("source_details", [])
        confirmed = bool(item.get("confirmed", True))
        status = str(item.get("status", "confirmed"))
        synthetic_fixture = bool(item.get("synthetic_fixture", False))
        real_scan = bool(item.get("real_scan", not synthetic_fixture))
        summary = (
            item.get("evidence", {}).get("summary")
            if isinstance(item.get("evidence"), dict)
            else None
        ) or f"Discovered subdomain {subdomain} for {domain}."
        findings.append(
            {
                "title": "Discovered subdomain",
                "severity": "info",
                "summary": summary,
                "evidence": [
                    {
                        "evidenceType": "subdomain-discovery",
                        "description": "Structured subdomain discovery evidence.",
                        "data": {
                            "findingType": "asset.subdomain",
                            "target": {"type": "domain", "value": domain},
                            "confidence": confidence,
                            "x-sentinelflow-subdomain.domain": domain,
                            "x-sentinelflow-subdomain.subdomain": subdomain,
                            "x-sentinelflow-subdomain.sources": sources,
                            "x-sentinelflow-subdomain.resolved": resolved,
                            "x-sentinelflow-subdomain.confirmed": confirmed,
                            "x-sentinelflow-subdomain.status": status,
                            "x-sentinelflow-subdomain.recordType": item.get(
                                "record_type", "unknown"
                            ),
                            "x-sentinelflow-subdomain.addresses": addresses,
                            "x-sentinelflow-subdomain.records": records,
                            "x-sentinelflow-subdomain.source_details": source_details,
                            "x-sentinelflow-run.mode": raw.get("mode"),
                            "x-sentinelflow-run.authorization_scope": raw.get("run_context", {}).get("authorization_scope") if isinstance(raw.get("run_context"), dict) else None,
                            "x-sentinelflow-fixture.synthetic": synthetic_fixture,
                            "x-sentinelflow-fixture.source": "local_fixture" if synthetic_fixture else None,
                            "x-sentinelflow-fixture.real_scan": real_scan,
                            "raw": item.get("raw", {}),
                        },
                    }
                ],
            }
        )

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

    return {"values": raw, "findings": findings, "errors": errors}


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
