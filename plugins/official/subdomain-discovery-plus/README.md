# Subdomain Discovery Plus

`subdomain-discovery-plus` is an official SentinelFlow command plugin for
authorized subdomain asset discovery. It combines deterministic passive fixture
input, optional Certificate Transparency lookup through `crt.sh`, and bounded
active DNS dictionary verification.

The plugin is independent from `plugins/official/subdomain-discovery/` and does
not replace or modify the passive-only plugin.

## Safety Boundary

- Only `target.type: domain` is accepted.
- `context.authorization_scope` is required.
- Passive fixture and optional `crt.sh` modes are read-only.
- Active dictionary DNS verification is low impact and is disabled unless
  `options.active.enabled=true` and `policy.allow_active_verify=true`.
- Active DNS is capped by `max_candidates`, `concurrency`, `rate_limit_per_second`,
  resolver count, record type count, and per-query timeout.
- Wordlist and fixture paths must stay inside this plugin directory.
- The plugin does not scan URLs, IP ranges, ports, services, vulnerabilities, weak
  credentials, bypass paths, stealth techniques, persistence, or attack chains.
- The runner executes out of process through the SentinelFlow Command Adapter.

## Modes

- `passive`: reads selected passive sources. The checked-in fixture is local and
  deterministic. `crt.sh` is contacted only when `crtsh_enabled=true`.
- `active`: reads a small wordlist, creates candidate subdomains, detects wildcard
  DNS, and verifies A/AAAA records.
- `hybrid`: runs passive first, then active, then merges duplicate subdomains.

`active.dry_run=true` reads and bounds the wordlist, reports the candidate count,
and performs no DNS queries. This is useful for planning a dictionary run.

## Input

Key fields:

- `target.value`: root domain such as `example.com`.
- `options.mode`: `passive`, `active`, or `hybrid`.
- `options.passive.sources`: `fixture`, `crtsh`, or both.
- `options.passive.fixture_file`: plugin-relative fixture JSON path.
- `options.passive.crtsh_enabled`: defaults to off in examples.
- `options.active.wordlist_file`: plugin-relative wordlist path.
- `options.active.resolvers`: resolver IPs, or `system` by itself.
- `options.active.record_types`: `A`, `AAAA`, or both.
- `options.active.timeout_seconds`: per DNS query timeout, 1-10 seconds.
- `options.active.concurrency`: maximum active lookup workers, 1-5.
- `options.active.rate_limit_per_second`: maximum candidate starts per second, 1-5.
- `options.active.max_candidates`: hard cap for dictionary candidates.
- `policy.allow_active_verify`: must be `true` for active DNS verification.

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

Duplicate subdomains are merged. If the same subdomain appears in passive and
active sources, sources are combined, DNS records are retained once, and
confidence is increased up to a safe cap.

## Wildcard DNS

When `detect_wildcard=true`, the runner resolves three randomized subdomains
under the target domain before dictionary enumeration. If at least two resolve,
wildcard DNS is marked in the summary. Active records matching the wildcard
address set are filtered. Active-only dictionary hits are then suppressed because
the zone behavior is ambiguous; in `hybrid` mode, active DNS can still enrich
subdomains already observed from passive sources, at lower confidence.

## Why Tests Use Fixtures

Unit and local acceptance tests use `example.com` and the local passive fixture so
they do not depend on network availability, resolver behavior, or external API
rate limits. `crt.sh` and active DNS may be useful in authorized environments,
but they are intentionally not required for CI stability.

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

target/debug/sentinelflow --workspace .sentinelflow tool run subdomain-discovery-plus \
  --input plugins/official/subdomain-discovery-plus/examples/input.active-dictionary.json \
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
