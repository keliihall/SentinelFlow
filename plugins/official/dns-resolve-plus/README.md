# dns-resolve-plus

`dns-resolve-plus` is an official SentinelFlow command plugin for DNS
fixture/cache validation. In P5.6 it is `disabled-p7-placeholder` /
`disabled-future`: live external DNS-intel, system resolver, public resolver,
and authoritative trace execution are not available.

## Modes

- `fixture`: reads only `examples/fixture.dns.example.com.json`; no network and
  no external API.
- `dry_run`: emits the plan summary only, including domain count, record types,
  estimated API/DNS query counts, and whether active verification is required.
- `passive_intel`: reads local fixture/cache/passive files; live external
  provider calls return `skipped_p7_disabled` in P5.6.
- `active`: P7 placeholder. It returns `P7_SCOPE_DISABLED` in P5.6.
- `hybrid`: P7 placeholder unless only local fixture/cache inputs are used.

## Sources

Supported sources are `fixture`, `local_cache`, `passive_dns_cache`,
`external_dns_intel`, `system_resolver`, `public_resolver`, and
`authoritative_trace` are schema-compatible P7 placeholders in P5.6. They do not
execute resolver or provider calls.

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
Provider secret channels are P7 work; P5.6 reports provider sources as
`skipped_p7_disabled`.

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
- system/public resolver: P7 placeholder in P5.6
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
