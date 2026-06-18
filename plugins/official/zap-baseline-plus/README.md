# zap-baseline-plus

`zap-baseline-plus` imports OWASP ZAP JSON or XML baseline reports and
normalizes passive alerts into SentinelFlow `risk.web_scan` findings.

The first version deliberately does not invoke ZAP, spider or connect to a
target, perform active scans, enter attack mode, use authentication, load
dynamic libraries, or accept arbitrary command arguments. Reports must be
regular files below this plugin directory and no larger than 4 MiB.

It supports per-instance URL evidence, risk and confidence normalization,
minimum risk/confidence filters, false-positive exclusion, deterministic
deduplication, HTML cleanup, secret redaction, and CWE/WASC metadata.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/zap-baseline-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/zap-baseline-plus
target/debug/sentinelflow --workspace .sentinelflow tool run zap-baseline-plus \
  --input plugins/official/zap-baseline-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target https://www.example.com
python3 -m unittest discover -s plugins/official/zap-baseline-plus/tests -v
```
