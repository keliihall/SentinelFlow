"""External service fingerprint facade with default graceful skip."""

from __future__ import annotations

import os
from typing import Any


SECRET_NAMES = [
    "SENTINELFLOW_SERVICE_INTEL_API_KEY",
    "SENTINELFLOW_FOFA_API_KEY",
    "SENTINELFLOW_SHODAN_API_KEY",
]


def query(services: list[dict[str, Any]], options: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    configured = [name for name in SECRET_NAMES if os.environ.get(name)]
    if not configured:
        return [], {
            "source": "external_fingerprint_intel",
            "status": "skipped_missing_secret",
            "message": "No service fingerprint intelligence secret is configured.",
            "query_count": 0,
        }
    return [], {
        "source": "external_fingerprint_intel",
        "status": "skipped_not_implemented",
        "message": "External fingerprint intelligence is configured but no provider endpoint is enabled in this release.",
        "query_count": 0,
        "configured_secret_names": configured,
        "service_count": len(services),
        "max_queries": options.get("max_queries"),
    }


def validate_external_tool_config(config: Any) -> bool:
    if config is None:
        return True
    if not isinstance(config, dict):
        return False
    allowed = {"tool", "profile"}
    return set(config).issubset(allowed) and config.get("tool") in {None, "fingerprint-only"}
