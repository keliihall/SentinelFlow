"""Passive DNS cache reader for dns-resolve-plus."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .local_cache import load_records


def load_passive_records(plugin_root: Path, relative_path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record in load_records(plugin_root, relative_path):
        item: dict[str, Any] = dict(record)
        item["source"] = "passive_dns_cache"
        item["source_type"] = "passive_intel"
        records.append(item)
    return records
