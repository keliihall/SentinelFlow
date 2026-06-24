# tls-certificate-check-plus

`tls-certificate-check-plus` is an official SentinelFlow command plugin for TLS
certificate fixture/cache validation. In P5.6 it is
`disabled-future`: live TLS handshakes are not available.

It reports subject, issuer, SAN names, validity window, days until expiry,
signature algorithm, TLS version, certificate-chain summary, expiry status,
source details, and confidence. Fixture/cache modes do not contact targets.
`policy.allow_active_verify=true` does not enable TLS handshakes in P5.6.

It does not scan ports, brute force hosts, test vulnerabilities, downgrade TLS,
send application payloads, fuzz, use credentials, or perform DoS-like activity.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without certificate output. |
| `passive_intel` | Local fixture/cache observations. |
| `active_tls` | P7 placeholder; returns `P7_SCOPE_DISABLED` in P5.6. |
| `hybrid` | P7 placeholder unless active is disabled and only local fixture/cache inputs are used. |

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
