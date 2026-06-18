"""Safe local-cache loader for dns-resolve-plus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SourceError(Exception):
    """Controlled source read error."""


def resolve_plugin_file(plugin_root: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or "\x00" in relative_path:
        raise SourceError("cache path must be plugin-relative without traversal")
    path = (plugin_root / relative).resolve()
    root = plugin_root.resolve()
    if not path.is_file() or root not in [path, *path.parents]:
        raise SourceError("cache path must resolve to a file inside the plugin")
    return path


def load_records(plugin_root: Path, relative_path: str) -> list[dict[str, Any]]:
    path = resolve_plugin_file(plugin_root, relative_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise SourceError("cache payload must contain a records array")
    return [item for item in records if isinstance(item, dict)]
