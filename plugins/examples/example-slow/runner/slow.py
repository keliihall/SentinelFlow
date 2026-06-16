#!/usr/bin/env python3
import json
import sys
import time

payload = json.load(sys.stdin)
time.sleep(2)
json.dump({"message": payload["message"]}, sys.stdout)

