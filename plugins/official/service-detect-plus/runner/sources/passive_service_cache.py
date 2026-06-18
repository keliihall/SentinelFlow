"""Passive service cache reader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .local_cache import load_services


def load_passive_services(plugin_root: Path, relative_path: str) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for item in load_services(plugin_root, relative_path):
        service: dict[str, Any] = dict(item)
        service["source"] = "passive_service_cache"
        service["source_type"] = "passive_intel"
        service["detection_depth"] = "passive"
        services.append(service)
    return services
