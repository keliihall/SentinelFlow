#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-.sentinelflow-asset-discovery-e2e}"

cargo build --workspace
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" init

target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin validate plugins/official/dns-resolve-plus
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin validate plugins/official/service-detect-plus
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin install plugins/official/dns-resolve-plus
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin install plugins/official/service-detect-plus

DNS_OUTPUT="$(mktemp)"
SERVICE_OUTPUT="$(mktemp)"

target/debug/sentinelflow --workspace "$WORKSPACE_DIR" tool run dns-resolve-plus \
  --input plugins/official/dns-resolve-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com > "$DNS_OUTPUT"

target/debug/sentinelflow --workspace "$WORKSPACE_DIR" tool run service-detect-plus \
  --input plugins/official/service-detect-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target 93.184.216.34:443 > "$SERVICE_OUTPUT"

python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); print(json.dumps({"tool": data["identifiers"]["toolId"], "status": data["status"], "findings": len(data["output"]["spec"].get("findings", []))}))' "$DNS_OUTPUT"
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); print(json.dumps({"tool": data["identifiers"]["toolId"], "status": data["status"], "findings": len(data["output"]["spec"].get("findings", []))}))' "$SERVICE_OUTPUT"

target/debug/sentinelflow --workspace "$WORKSPACE_DIR" task validate \
  docs/examples/task.subdomain-dns-port-service.fixture.yaml
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" task plan \
  docs/examples/task.subdomain-dns-port-service.fixture.yaml
