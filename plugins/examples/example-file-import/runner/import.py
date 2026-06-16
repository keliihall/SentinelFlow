#!/usr/bin/env python3
"""Normalize bounded synthetic records supplied over stdin."""

import json
import sys


def main() -> int:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        return 2
    source = value.get("source")
    records = value.get("records")
    if not isinstance(source, str) or not isinstance(records, list):
        return 2
    json.dump({"source": source, "records": records}, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
