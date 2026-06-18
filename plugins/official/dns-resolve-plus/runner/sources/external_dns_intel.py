"""External passive DNS intelligence source facade.

The facade intentionally does not hard-code third-party API endpoints. Real API
adapters must be added only after checking current official provider docs.
"""

from __future__ import annotations

import os
from typing import Any


SECRET_NAMES = [
    "SENTINELFLOW_DNS_INTEL_API_KEY",
    "SENTINELFLOW_SECURITYTRAILS_API_KEY",
    "SENTINELFLOW_VIRUSTOTAL_API_KEY",
    "SENTINELFLOW_CENSYS_API_ID",
    "SENTINELFLOW_CENSYS_API_SECRET",
]


def query(domains: list[str], record_types: list[str], options: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    configured = [name for name in SECRET_NAMES if os.environ.get(name)]
    if not configured:
        return [], {
            "source": "external_dns_intel",
            "status": "skipped_missing_secret",
            "message": "No DNS intelligence API secret is configured.",
            "query_count": 0,
        }
    return [], {
        "source": "external_dns_intel",
        "status": "skipped_not_implemented",
        "message": "External DNS intelligence adapter is configured but no provider endpoint is enabled in this release.",
        "query_count": 0,
        "configured_secret_names": configured,
        "domain_count": len(domains),
        "record_types": record_types,
        "max_queries": options.get("max_queries"),
    }
