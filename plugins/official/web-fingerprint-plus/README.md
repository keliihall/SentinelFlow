# web-fingerprint-plus

`web-fingerprint-plus` is an official SentinelFlow command plugin for passive
Web technology fingerprinting. It consumes fixture/cache observations or
upstream `http-probe-plus` Findings and emits normalized `asset.web_fingerprint`
Findings.

It can identify CMS, Web frameworks, JavaScript frameworks, middleware, CDN/WAF
signals, favicon hashes, header clues, and low-impact body/title features. It
does not make network requests, crawl, brute force paths, test vulnerabilities,
send payloads, use credentials, fuzz, or perform DoS-like activity.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without fingerprint output. |
| `passive_intel` | Local fixture/cache observations. |
| `from_http_probe` | Upstream `http-probe-plus` Findings or observations. |

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/web-fingerprint-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/web-fingerprint-plus
target/debug/sentinelflow --workspace .sentinelflow tool run web-fingerprint-plus \
  --input plugins/official/web-fingerprint-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/web-fingerprint-plus/tests -v
```
