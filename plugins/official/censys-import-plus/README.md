# censys-import-plus

`censys-import-plus` is an official SentinelFlow command plugin for importing
Censys-style host, service, and certificate intelligence through the standard
Manifest, Command Adapter, built-in Parser, Schema, Normalizer, Policy, and
Audit path.

The first version is fixture/cache first. A provider facade can be enabled by
configuration, but the runner never accepts arbitrary Censys query strings and
never emits `CENSYS_API_ID` or `CENSYS_API_SECRET`. Missing credentials are
reported as `skipped_missing_secret` when `allow_missing_secret=true`.

## Modes

- `fixture`: read repository fixture data for deterministic CI.
- `dry_run`: validate target-derived query planning without returning results.
- `local_cache`: read a bounded local cache file.
- `api_lookup`: check provider readiness and secret presence.
- `hybrid`: merge cache and provider observations.

## Safety

- Queries are constructed from the authorized target only.
- `ip` scope requires a syntactically valid IP address.
- User query metacharacters are rejected for every scope.
- Active target connections are always `0`.
- Secrets are not accepted in input and are never written to output.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/censys-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/censys-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run censys-import-plus \
  --input plugins/official/censys-import-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target 93.184.216.34
python3 -m unittest discover -s plugins/official/censys-import-plus/tests -v
```
