# shodan-import-plus

`shodan-import-plus` is an official SentinelFlow command plugin for importing
Shodan-style host exposure intelligence into the standard Finding/Evidence
pipeline.

It supports IP, domain, organization, and certificate-fingerprint lookup scopes.
The lookup intent is always derived from the authorized target and structured
scope; the plugin does not accept arbitrary Shodan search strings. Fixture and
local-cache modes are deterministic for CI. Provider lookup requires
`SHODAN_API_KEY`; missing secrets are reported as `skipped_missing_secret`, not
task failure.

Imported fields include host, IP, port, protocol, service, banner summary,
HTTP title, certificate metadata, first/last seen timestamps, source details,
and confidence. The runner never emits API keys or raw secret-bearing requests.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Show target-derived lookup intent without importing results. |
| `local_cache` | Import from a local cache file. |
| `api_lookup` | Secret-gated provider lookup facade. |
| `hybrid` | Local cache plus provider lookup facade. |

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/shodan-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/shodan-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run shodan-import-plus \
  --input plugins/official/shodan-import-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target 93.184.216.34
python3 -m unittest discover -s plugins/official/shodan-import-plus/tests -v
```
