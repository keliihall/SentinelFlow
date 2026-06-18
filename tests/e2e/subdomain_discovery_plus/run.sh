#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

cargo build --workspace

WORKSPACE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sentinelflow-subdomain-plus.XXXXXX")/.sentinelflow"
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" init
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin validate plugins/official/subdomain-discovery-plus
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" plugin install plugins/official/subdomain-discovery-plus
target/debug/sentinelflow --workspace "$WORKSPACE_DIR" tool run subdomain-discovery-plus \
  --input plugins/official/subdomain-discovery-plus/examples/input.passive-fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
