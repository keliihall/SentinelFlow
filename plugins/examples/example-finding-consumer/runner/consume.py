#!/usr/bin/env python3
import json
import sys

payload = json.load(sys.stdin)
findings = payload.get("findings")
if not isinstance(findings, list):
    raise SystemExit(2)
json.dump({"message": f"consumed {len(findings)} finding(s)"}, sys.stdout)

