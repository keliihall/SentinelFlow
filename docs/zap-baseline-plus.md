# zap-baseline-plus

`zap-baseline-plus` is the official SentinelFlow adapter for bounded OWASP ZAP
baseline report import. It accepts ZAP JSON and XML exports, expands alert
instances, applies risk/confidence policy filters, and normalizes accepted
records through Schema, built-in Parser, Normalizer, Policy, and Audit controls.

## Supported data

- Site URL, host, port, and TLS flag.
- Alert/plugin id, alert reference, name, risk, and confidence.
- Instance URL, HTTP method, parameter, attack, evidence, and extra detail.
- Description, remediation, references, CWE, WASC, and source id.
- Duplicate suppression and optional false-positive import.

HTML report text is reduced to plain text. Secret-like values and authorization
headers are redacted before output.

## Safety boundary

This release is an offline report adapter. It cannot invoke ZAP, start spiders,
connect to targets, perform active scans, authenticate, or enter attack mode.
All corresponding policy fields are schema-locked to `false`. Input files must
resolve under `plugins/official/zap-baseline-plus/` and are limited to 4 MiB.

## Acceptance

```bash
cargo build -p sentinelflow-cli
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/zap-baseline-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/zap-baseline-plus
target/debug/sentinelflow --workspace .sentinelflow tool run zap-baseline-plus \
  --input plugins/official/zap-baseline-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target https://www.example.com
python3 -m unittest discover -s plugins/official/zap-baseline-plus/tests -v
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```
