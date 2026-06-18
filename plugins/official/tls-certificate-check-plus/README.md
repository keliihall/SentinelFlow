# tls-certificate-check-plus

`tls-certificate-check-plus` is an official SentinelFlow command plugin for TLS
certificate inventory and low-impact certificate health checks.

It reports subject, issuer, SAN names, validity window, days until expiry,
signature algorithm, TLS version, certificate-chain summary, expiry status,
source details, and confidence. Fixture/cache modes do not contact targets.
Active TLS inspection performs only a bounded TLS handshake and requires
`policy.allow_active_verify=true`.

It does not scan ports, brute force hosts, test vulnerabilities, downgrade TLS,
send application payloads, fuzz, use credentials, or perform DoS-like activity.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without certificate output. |
| `passive_intel` | Local fixture/cache observations. |
| `active_tls` | Bounded TLS handshake certificate inspection. |
| `hybrid` | Passive observations plus bounded TLS verification. |

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/tls-certificate-check-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/tls-certificate-check-plus
target/debug/sentinelflow --workspace .sentinelflow tool run tls-certificate-check-plus \
  --input plugins/official/tls-certificate-check-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/tls-certificate-check-plus/tests -v
```
