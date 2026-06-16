#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build -p sentinelflow-api -p sentinelflow-cli
python3 tests/performance/performance_baseline.py "$@"
