#!/usr/bin/env python3
import json
import sys

payload = json.load(sys.stdin)
json.dump({"message": payload["message"]}, sys.stdout)

