"""Extract service observations from upstream normalized Findings."""

from __future__ import annotations

from typing import Any


def extract(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[Any] = []
    inputs = payload.get("inputs")
    if isinstance(inputs, dict) and isinstance(inputs.get("findings"), list):
        candidates.extend(inputs["findings"])
    if isinstance(payload.get("findings"), list):
        candidates.extend(payload["findings"])

    services: list[dict[str, Any]] = []
    for finding in candidates:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            data = evidence.get("data")
            if not isinstance(data, dict):
                continue
            service = from_evidence_data(data)
            if service:
                services.append(service)
    return services


def from_evidence_data(data: dict[str, Any]) -> dict[str, Any] | None:
    address = data.get("x-sentinelflow-service.address") or data.get("x-sentinelflow-port.address")
    port = data.get("x-sentinelflow-service.port") or data.get("x-sentinelflow-port.port")
    if not isinstance(address, str) or not isinstance(port, int):
        return None
    source_details = data.get("x-sentinelflow-port.source_details") or data.get("x-sentinelflow-service.source_details") or []
    return {
        "address": address,
        "port": port,
        "protocol": data.get("x-sentinelflow-service.protocol") or data.get("x-sentinelflow-port.protocol") or "tcp",
        "service": data.get("x-sentinelflow-service.service") or data.get("x-sentinelflow-port.service") or "unknown",
        "transport": data.get("x-sentinelflow-service.transport"),
        "product": data.get("x-sentinelflow-service.product") or data.get("x-sentinelflow-port.product"),
        "version": data.get("x-sentinelflow-service.version") or data.get("x-sentinelflow-port.version"),
        "hostnames": data.get("x-sentinelflow-service.hostnames") or data.get("x-sentinelflow-port.hostnames") or [],
        "banner_summary": data.get("x-sentinelflow-service.banner_summary") or data.get("x-sentinelflow-port.banner_summary"),
        "http": data.get("x-sentinelflow-service.http") or {},
        "tls": data.get("x-sentinelflow-service.tls") or {},
        "source": "upstream_port_result",
        "source_type": "passive_intel",
        "detection_depth": "passive",
        "source_details": source_details if isinstance(source_details, list) else [],
        "confidence": data.get("confidence", 0.80),
    }
