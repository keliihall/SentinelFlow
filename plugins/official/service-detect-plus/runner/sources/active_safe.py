"""Bounded safe active service identification helpers."""

from __future__ import annotations

import socket
from typing import Any


def tcp_banner(service: dict[str, Any], timeout_seconds: int, max_response_bytes: int) -> dict[str, Any] | None:
    address = str(service.get("address", ""))
    port = int(service.get("port", 0))
    if not address or port <= 0:
        return None
    with socket.create_connection((address, port), timeout=timeout_seconds) as connection:
        connection.settimeout(timeout_seconds)
        try:
            data = connection.recv(max_response_bytes)
        except TimeoutError:
            data = b""
    if not data:
        return None
    return {
        "address": address,
        "port": port,
        "protocol": service.get("protocol", "tcp"),
        "service": service.get("service", "unknown"),
        "transport": None,
        "product": None,
        "version": None,
        "hostnames": service.get("hostnames", []),
        "banner_summary": data.decode("utf-8", errors="replace"),
        "http": {},
        "tls": {},
        "source": "tcp_banner",
        "source_type": "active",
        "detection_depth": "safe",
        "confidence": 0.80,
    }
