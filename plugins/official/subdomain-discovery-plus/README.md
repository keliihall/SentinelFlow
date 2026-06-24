# Subdomain Discovery Plus

`subdomain-discovery-plus` is an official SentinelFlow command plugin for P5.6
fixture-only subdomain validation. It uses deterministic local fixture input for
`example.com` / `example.test`; live Certificate Transparency lookup and active
DNS dictionary verification are disabled P7 placeholders.

The plugin is independent from `plugins/official/subdomain-discovery/` and does
not replace or modify the passive-only plugin.

## Safety Boundary

- Only `target.type: domain` is accepted.
- `context.authorization_scope` is required.
- Passive fixture and local cache modes are read-only.
- Live `crt.sh`, FOFA, Shodan, Censys, SecurityTrails, VirusTotal, and active DNS
  resolver verification return `skipped_p7_disabled` / `P7_SCOPE_DISABLED` in
  P5.6.
- `active.dry_run=true` may be used only to count bounded dictionary candidates;
  it performs no DNS queries.
- Wordlist and fixture paths must stay inside this plugin directory.
- The plugin does not scan URLs, IP ranges, ports, services, vulnerabilities, weak
  credentials, bypass paths, stealth techniques, persistence, or attack chains.
- The runner executes out of process through the SentinelFlow Command Adapter.

## Modes

- `passive` / `fixture`: reads selected local fixture sources. The checked-in
  fixtures are deterministic and do not contact any provider.
- `active`: P7 placeholder. Non-dry-run active DNS is rejected in P5.6.
- `hybrid`: P7 placeholder unless active is disabled and only local fixture/cache
  inputs are used.

`active.dry_run=true` reads and bounds the wordlist, reports the candidate count,
and performs no DNS queries. This is useful for planning a dictionary run.

## Input

Key fields:

- `target.value`: root domain such as `example.com`.
- `options.mode`: `passive`, `active`, or `hybrid`.
- `options.passive.sources`: use `fixture` for P5.6. Other provider names are
  compatibility placeholders and return disabled status.
- `options.passive.fixture_file`: plugin-relative fixture JSON path.
- `options.passive.crtsh_enabled`: compatibility field; live queries are disabled
  in P5.6.
- `options.active.wordlist_file`: plugin-relative wordlist path.
- `options.active.resolvers`: keep empty in P5.6 examples.
- `options.active.record_types`: `A`, `AAAA`, or both.
- `options.active.timeout_seconds`: per DNS query timeout, 1-10 seconds.
- `options.active.concurrency`: maximum active lookup workers, 1-5.
- `options.active.rate_limit_per_second`: maximum candidate starts per second, 1-5.
- `options.active.max_candidates`: hard cap for dictionary candidates.
- `policy.allow_active_verify`: does not enable active DNS in P5.6.

## Output

The runner emits one JSON object validated by `schemas/output.schema.json`.
Each entry in `findings[]` includes:

- `domain`
- `subdomain`
- `source` and merged `sources`
- `resolved`
- `record_type`
- `addresses`
- `records`
- `confidence`
- `evidence.summary`
- `raw` with bounded, non-sensitive retained metadata

The trusted built-in parser `subdomain-discovery-plus-v1` converts each raw
subdomain entry into an informational SentinelFlow Finding with structured
Evidence. Because current v1alpha1 Findings do not expose arbitrary per-finding
extensions, the `x-sentinelflow-subdomain.*` fields are stored under
`evidence.data`.

Duplicate subdomains from local fixture/cache inputs are merged. Active-source
merging is P7 proposal behavior.

## Wildcard DNS

Wildcard DNS checks require active resolver queries and are disabled in P5.6.

## Why Tests Use Fixtures

Unit and local acceptance tests use `example.com` / `example.test` and local
fixtures so they do not depend on network availability, resolver behavior, or
external API rate limits.

## Acceptance Commands

```sh
cargo build --workspace

target/debug/sentinelflow --workspace .sentinelflow init

target/debug/sentinelflow --workspace .sentinelflow plugin validate \
  plugins/official/subdomain-discovery-plus

target/debug/sentinelflow --workspace .sentinelflow plugin install \
  plugins/official/subdomain-discovery-plus

target/debug/sentinelflow --workspace .sentinelflow tool list

target/debug/sentinelflow --workspace .sentinelflow tool run subdomain-discovery-plus \
  --input plugins/official/subdomain-discovery-plus/examples/input.passive-fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com

target/debug/sentinelflow --workspace .sentinelflow task validate \
  plugins/official/subdomain-discovery-plus/examples/task.passive-fixture.yaml

target/debug/sentinelflow --workspace .sentinelflow task plan \
  plugins/official/subdomain-discovery-plus/examples/task.passive-fixture.yaml

target/debug/sentinelflow --workspace .sentinelflow task run \
  plugins/official/subdomain-discovery-plus/examples/task.passive-fixture.yaml

target/debug/sentinelflow --workspace .sentinelflow report generate --run <RUN_ID>
```

For active dictionary tasks, use:

```sh
target/debug/sentinelflow --workspace .sentinelflow task validate \
  plugins/official/subdomain-discovery-plus/examples/task.active-dictionary.yaml

target/debug/sentinelflow --workspace .sentinelflow task plan \
  plugins/official/subdomain-discovery-plus/examples/task.active-dictionary.yaml

target/debug/sentinelflow --workspace .sentinelflow task run \
  plugins/official/subdomain-discovery-plus/examples/task.active-dictionary.yaml
```

The checked-in active example uses `active.dry_run=true`, so it validates the
active policy gate and bounded candidate planning without sending DNS queries.
Set `active.dry_run=false` only in an authorized environment where active DNS
verification is expected.

If `options.active.enabled=true` but `policy.allow_active_verify=false`, the
runner returns a standard `PolicyDenied` parser error and performs zero DNS
queries.

## Development Checks

```sh
python3 -m unittest discover -s plugins/official/subdomain-discovery-plus/tests -v
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
