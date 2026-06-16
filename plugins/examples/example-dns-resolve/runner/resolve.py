#!/usr/bin/env python3
"""Resolve synthetic names from an embedded table without network access."""

import json
import sys

RECORDS = {
    "fixture.local": ["192.0.2.10", "2001:db8::10"],
    "empty.fixture.local": [],
}


def main() -> int:
    value = json.load(sys.stdin)
    hostname = value.get("hostname") if isinstance(value, dict) else None
    if hostname not in RECORDS:
        return 2
    json.dump(
        {"hostname": hostname, "addresses": RECORDS[hostname], "source": "embedded-fixture"},
        sys.stdout,
        separators=(",", ":"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
