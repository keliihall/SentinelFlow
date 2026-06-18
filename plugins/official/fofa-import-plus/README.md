# fofa-import-plus

`fofa-import-plus` is an official SentinelFlow command plugin for importing
FOFA-style public exposure intelligence into the standard Finding/Evidence
pipeline.

It supports domain, IP, organization, and certificate-fingerprint lookup scopes.
The query is always constructed from the authorized target and structured scope;
the plugin does not accept arbitrary FOFA query strings. Fixture and local-cache
modes are deterministic for CI. Provider lookup requires `FOFA_API_KEY`; missing
secrets are reported as `skipped_missing_secret`, not task failure.

Imported fields include host, IP, port, protocol, service, title, headers,
certificate metadata, source details, and confidence. The runner masks secret
presence and never writes API keys to output, logs, reports, or audit data.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Show target-derived query intent without importing results. |
| `local_cache` | Import from a local cache file. |
| `api_lookup` | Secret-gated provider lookup facade. |
| `hybrid` | Local cache plus provider lookup facade. |

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/fofa-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/fofa-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run fofa-import-plus \
  --input plugins/official/fofa-import-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/fofa-import-plus/tests -v
```
