#!/usr/bin/env python3
"""Parser contract helper for port-probe-plus runner output."""

from __future__ import annotations

import json
import sys
from typing import Any


def parse(raw: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for item in raw.get("results", []):
        if not isinstance(item, dict) or item.get("type") != "port_result":
            continue
        address = str(item.get("address", ""))
        port = item.get("port")
        protocol = str(item.get("protocol", "tcp"))
        summary = (
            item.get("evidence", {}).get("summary")
            if isinstance(item.get("evidence"), dict)
            else None
        ) or f"Port {port}/{protocol} on {address} observed as open."
        findings.append(
            {
                "title": "Open port observed",
                "severity": "info",
                "summary": summary,
                "evidence": [
                    {
                        "evidenceType": "port-probe",
                        "description": "Structured port exposure evidence.",
                        "data": {
                            "findingType": "asset.port_probe",
                            "target": {"type": "service", "value": f"{address}:{port}"},
                            "confidence": item.get("confidence", 0),
                            "x-sentinelflow-port.address": address,
                            "x-sentinelflow-port.port": port,
                            "x-sentinelflow-port.protocol": protocol,
                            "x-sentinelflow-port.state": item.get("state"),
                            "x-sentinelflow-port.service": item.get("service"),
                            "x-sentinelflow-port.hostnames": item.get("hostnames", []),
                            "x-sentinelflow-port.sources": item.get("sources", []),
                            "x-sentinelflow-port.source_details": item.get("source_details", []),
                            "x-sentinelflow-port.source_count": item.get("source_count", 0),
                            "x-sentinelflow-port.source_agreement": item.get("source_agreement", "unknown"),
                            "x-sentinelflow-port.passive_only": item.get("passive_only", False),
                            "x-sentinelflow-port.active_verified": item.get("active_verified", False),
                            "x-sentinelflow-port.conflict": item.get("conflict", False),
                            "x-sentinelflow-port.conflict_reason": item.get("conflict_reason"),
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
