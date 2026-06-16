#!/usr/bin/env python3
"""Safe fixture runner: echo one bounded JSON string from stdin to stdout."""

import json
import sys


def main() -> int:
    value = json.load(sys.stdin)
    if not isinstance(value, dict) or not isinstance(value.get("message"), str):
        return 2
    json.dump({"message": value["message"]}, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

