# dns-resolve-plus

`dns-resolve-plus` is an official SentinelFlow command plugin for DNS
resolution and DNS intelligence multi-source validation. It is passive-intel
first: fixture, local cache, passive DNS cache, and external DNS-intel facades
are preferred; active DNS resolution is an explicit policy-gated supplement.

## Modes

- `fixture`: reads only `examples/fixture.dns.example.com.json`; no network and
  no external API.
- `dry_run`: emits the plan summary only, including domain count, record types,
  estimated API/DNS query counts, and whether active verification is required.
- `passive_intel`: reads fixture/cache/passive sources and gracefully skips
  external DNS-intel when secrets are absent.
- `active`: runs bounded resolver work only when
  `policy.allow_active_verify=true`.
- `hybrid`: passive first, then optional active verification, then merge.

## Sources

Supported sources are `fixture`, `local_cache`, `passive_dns_cache`,
`external_dns_intel`, `system_resolver`, `public_resolver`, and
`authoritative_trace`. `external_dns_intel` accepts only provider adapters built
by SentinelFlow; this release does not hard-code provider endpoints. Missing
secrets produce `source_status.status=skipped_missing_secret` and do not fail the
task.

Provider integrations should use SentinelFlow secret/config once that channel is
available for official plugins. The current v1alpha1 runtime reserves the
`SENTINELFLOW_*` environment prefix and does not allow plugins to inherit those
variables directly. Planned secret names are:

- `SENTINELFLOW_DNS_INTEL_API_KEY`
- `SENTINELFLOW_SECURITYTRAILS_API_KEY`
- `SENTINELFLOW_VIRUSTOTAL_API_KEY`
- `SENTINELFLOW_CENSYS_API_ID`
- `SENTINELFLOW_CENSYS_API_SECRET`

Do not put real API keys in code, docs, fixtures, tests, reports, or task specs.
Without a configured secret channel, the source is reported as
`skipped_missing_secret`.

## Merge And Confidence

All source rows are normalized to observations before merge. DNS deduplication
uses `domain + record_type + value`. Merged results preserve `sources` and
`source_details`.

`source_agreement` can be `consistent`, `passive_only`, `active_only`,
`conflict`, `stale_passive`, `unresolved`, or `unknown`. Conflicting values are
not overwritten; they are emitted as separate merged results with
`conflict=true` and `conflict_reason=dns_value_mismatch`.

Confidence starts from source weights:

- fixture/local cache: 0.70
- passive DNS cache: 0.75
- external DNS intel: 0.80
- system/public resolver: 0.85
- authoritative trace: 0.90

Multiple sources and passive-active agreement raise confidence; stale or
conflicting sources lower it. Final confidence is clamped to `[0, 1]`.

## Safety Boundary

Default execution is non-intrusive and fixture/cache based. Active resolver work
requires `policy.allow_active_verify=true`. `authoritative_trace` also requires
`options.risk_acknowledged=true`. The runner never accepts shell strings,
arbitrary query language, absolute cache paths, or parent-directory traversal.

CI and E2E should use `fixture` or `passive_intel` with local fixture/cache
inputs. Active examples are provided for policy explanation and authorized
manual validation only.

## Parser

The manifest selects trusted built-in parser `dns-resolve-plus-v1`. The parser
emits informational `asset.dns_resolve` Findings with structured Evidence fields
under `x-sentinelflow-dns.*`.

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/dns-resolve-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/dns-resolve-plus
target/debug/sentinelflow --workspace .sentinelflow tool run dns-resolve-plus \
  --input plugins/official/dns-resolve-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/dns-resolve-plus/tests -v
```
