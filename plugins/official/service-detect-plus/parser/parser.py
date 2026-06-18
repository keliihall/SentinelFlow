#!/usr/bin/env python3
"""Parser contract helper for service-detect-plus runner output."""

from __future__ import annotations

import json
import sys
from typing import Any


def parse(raw: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for item in raw.get("results", []):
        if not isinstance(item, dict) or item.get("type") != "service_result":
            continue
        service = str(item.get("service", "unknown"))
        address = str(item.get("address", ""))
        port = item.get("port")
        summary = (
            item.get("evidence", {}).get("summary")
            if isinstance(item.get("evidence"), dict)
            else None
        ) or f"Service on {address}:{port} identified as {service}."
        findings.append(
            {
                "title": "Service observed",
                "severity": "info",
                "summary": summary,
                "evidence": [
                    {
                        "evidenceType": "service-detection",
                        "description": "Structured service detection evidence.",
                        "data": {
                            "findingType": "asset.service_detect",
                            "target": {"type": "service", "value": f"{address}:{port}"},
                            "confidence": item.get("confidence", 0),
                            "x-sentinelflow-service.address": address,
                            "x-sentinelflow-service.port": port,
                            "x-sentinelflow-service.protocol": item.get("protocol"),
                            "x-sentinelflow-service.service": service,
                            "x-sentinelflow-service.transport": item.get("transport"),
                            "x-sentinelflow-service.product": item.get("product"),
                            "x-sentinelflow-service.version": item.get("version"),
                            "x-sentinelflow-service.hostnames": item.get("hostnames", []),
                            "x-sentinelflow-service.http": item.get("http", {}),
                            "x-sentinelflow-service.tls": item.get("tls", {}),
                            "x-sentinelflow-service.sources": item.get("sources", []),
                            "x-sentinelflow-service.source_details": item.get("source_details", []),
                            "x-sentinelflow-service.source_count": item.get("source_count", 0),
                            "x-sentinelflow-service.source_agreement": item.get("source_agreement", "unknown"),
                            "x-sentinelflow-service.conflict": item.get("conflict", False),
                            "x-sentinelflow-service.conflict_reason": item.get("conflict_reason"),
                            "x-sentinelflow-service.detection_depth": item.get("detection_depth"),
                            "x-sentinelflow-service.risk_level": item.get("risk_level"),
                            "x-sentinelflow-service.observed_at": item.get("observed_at"),
                            "x-sentinelflow-service.stale": item.get("stale", False),
                            "x-sentinelflow-service.confidence_strategy": item.get("confidence_strategy"),
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
