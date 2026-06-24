# service-detect-plus

`service-detect-plus` is an official SentinelFlow command plugin for service
fixture/cache validation. In P5.6 it is `disabled-p7-placeholder`: active service
probing and live external fingerprint/intelligence provider calls are not
available.

## Modes And Depth

Modes are `fixture`, `dry_run`, `passive_intel`, `active`, and `hybrid`.

Detection depth is one of `fixture`, `passive`, `safe`, `standard`, `deep`, or
`external_fingerprint`.

- `fixture`: reads only `examples/fixture.services.example.com.json`.
- `passive_intel`: local fixture/cache/upstream findings only in P5.6; live
  external providers return `skipped_p7_disabled`.
- `active` with `safe` or `standard`: P7 placeholder; returns
  `P7_SCOPE_DISABLED` in P5.6.
- `deep` and `external_fingerprint`: outside P5.6.

## Sources

Supported sources are `fixture`, `local_cache`, `upstream_port_result`,
`upstream_dns_result`, `passive_service_cache`, `fofa_enrichment`,
`shodan_enrichment`, `external_fingerprint_intel`, `tcp_banner`, `tls_hello`,
`http_head`, `http_get_root`, `standard_probe`, `deep_probe`, and
`external_fingerprint`.

The plugin prefers `upstream_port_result`; FOFA/Shodan enrichment is extracted
from upstream source details when present to avoid duplicate external API calls.
Live external fingerprint provider calls produce
`source_status.status=skipped_p7_disabled` in P5.6.

Provider integrations should use SentinelFlow secret/config once that channel is
available for official plugins. The current v1alpha1 runtime reserves the
`SENTINELFLOW_*` environment prefix and does not allow plugins to inherit those
variables directly. Planned secret names are:

- `SENTINELFLOW_SERVICE_INTEL_API_KEY`
- `SENTINELFLOW_FOFA_API_KEY`
- `SENTINELFLOW_SHODAN_API_KEY`

Never put real API keys, cookies, tokens, production targets, weak password
lists, exploit payloads, fuzzing payloads, or DoS tests in code, docs, fixtures,
tests, reports, or task specs.

## Merge And Confidence

All source rows are normalized before merge. Service deduplication uses:

`address + protocol + port + service + product + version`

The base service key is:

`address + protocol + port`

Merged results preserve source details and can mark `consistent`,
`passive_only`, `active_only`, `conflict`, `stale_passive`, or `unknown`.
Conflicts are preserved with `conflict_reason=service_product_mismatch` or
`product_version_mismatch`.

Confidence starts from source weights:

- fixture/local cache: 0.70
- upstream port result: 0.80
- passive service cache: 0.75
- FOFA/Shodan enrichment: 0.80/0.85
- safe active probes: P7 placeholder in P5.6
- standard/deep/external fingerprint: 0.90/0.92/0.85

Multiple agreeing local/passive sources raise confidence. Stale
passive results, service/product conflicts, and weak banners lower it. Final
confidence is clamped to `[0, 1]`.

## Safety Boundary

Default execution is non-intrusive. Active probes are bounded by timeout,
concurrency, rate limit, max services, max probes per service, and max response
bytes. The runner masks sensitive headers and truncates banner/title/header
data. It rejects arbitrary command, script, path dictionary, exploit, brute
force, fuzzing, DoS, and path-scanning configuration.

CI and default E2E should run `fixture` only. `high-risk-deep.example` is for
validate/plan/policy explanation in authorized labs; it is not a default run
fixture.

## Parser

The manifest selects trusted built-in parser `service-detect-plus-v1`. The
parser emits informational `asset.service_detect` Findings with structured
Evidence fields under `x-sentinelflow-service.*`.

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/service-detect-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/service-detect-plus
target/debug/sentinelflow --workspace .sentinelflow tool run service-detect-plus \
  --input plugins/official/service-detect-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target 93.184.216.34:443
python3 -m unittest discover -s plugins/official/service-detect-plus/tests -v
```
