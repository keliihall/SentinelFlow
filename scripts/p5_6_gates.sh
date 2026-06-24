#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

gate() {
  printf '\n==> %s\n' "$1"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_command cargo
require_command python3
require_command node

gate "P56-G01 Rust formatting"
cargo fmt --all -- --check

gate "P56-G02 Rust lint"
cargo clippy --workspace --all-targets --all-features -- -D warnings

gate "P56-G03 Rust tests"
cargo test --workspace --all-features

gate "P56-G04 CLI/API/Web consistency"
tests/e2e/p5_5_consistency.sh

gate "P56-G05 Plugin Manifest validation"
cargo test -p sentinelflow-registry --all-features --test plugin_contract
cargo build -p sentinelflow-cli --all-features
manifest_count=0
while IFS= read -r -d '' manifest; do
  plugin_root="$(dirname "$manifest")"
  target/debug/sentinelflow plugin validate "$plugin_root"
  manifest_count=$((manifest_count + 1))
done < <(find plugins -type f -name sentinelflow.tool.yaml -print0)
if [[ "$manifest_count" -eq 0 ]]; then
  printf 'no plugin Manifests were discovered\n' >&2
  exit 1
fi
printf 'validated %s plugin Manifests\n' "$manifest_count"

gate "P56-G06 Policy/Audit/Approval coverage"
cargo test -p sentinelflow-policy --all-features
tests/e2e/p5_5_security/run.sh

gate "P56-G07 Report redaction"
cargo test -p sentinelflow-report --all-features \
  reports_redact_sensitive_evidence_and_error_text

gate "P56-G08 Web unit smoke"
node --test crates/sentinelflow-api/web/*.test.js

gate "P56-G10 Web Quick Run fixture-only scope guard"
node --test crates/sentinelflow-api/web/*.test.js
node scripts/p5_6_scope_guard.js

gate "P56-G09 Web/API basic smoke"
tests/e2e/p5_5_smoke.sh

printf '\nSentinelFlow P5.6 release gates passed.\n'
