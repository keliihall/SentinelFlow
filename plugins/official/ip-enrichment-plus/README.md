# ip-enrichment-plus

`ip-enrichment-plus` is an official SentinelFlow command plugin for passive IP
enrichment and local IP classification.

It enriches IP assets with ASN, organization, ISP, geolocation, cloud provider,
CDN, WAF, and address category signals. The first version is fixture/cache
first; provider facades are secret-gated and report graceful skips when tokens
are missing. The runner never connects to the target IP.

## Modes

- `fixture`: deterministic repository fixture import.
- `dry_run`: classify the target and report planned passive sources.
- `local_cache`: read a bounded local cache file.
- `provider_lookup`: check provider readiness and secret presence.
- `hybrid`: merge cache and provider observations.

## Safety

- Active target connections are always `0`.
- Provider secrets are read only from allowlisted environment variables.
- Missing provider tokens are represented as `skipped_missing_secret`.
- Private, loopback, link-local, multicast, documentation, reserved, and
  unspecified addresses are classified locally and marked as not public.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/ip-enrichment-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/ip-enrichment-plus
target/debug/sentinelflow --workspace .sentinelflow tool run ip-enrichment-plus \
  --input plugins/official/ip-enrichment-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target 93.184.216.34
python3 -m unittest discover -s plugins/official/ip-enrichment-plus/tests -v
```
