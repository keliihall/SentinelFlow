# crtsh-subdomain-plus

`crtsh-subdomain-plus` is an official SentinelFlow command plugin for passive
certificate transparency import. It extracts subdomains and certificate SAN
assets from crt.sh-style fixture/cache data and emits normalized Findings
through the trusted built-in parser.

The first version does not connect to targets, brute force DNS, probe ports, or
load untrusted code in-process. Provider lookup is represented as a facade so
configured deployments can wire an approved client later without changing Core.

## Modes

- `fixture`: deterministic repository fixture import.
- `dry_run`: validate target-derived lookup planning.
- `local_cache`: read a bounded local cache file.
- `api_lookup`: provider facade status only.
- `hybrid`: merge local cache and provider observations.

## Safety

- Target type is domain-only.
- Wildcard names such as `*.example.com` are cleaned to `example.com`-scoped
  hostnames and marked in source details.
- Names outside the authorized target domain are discarded.
- Active target connections are always `0`.
- No credentials are required and no arbitrary query strings are accepted.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/crtsh-subdomain-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/crtsh-subdomain-plus
target/debug/sentinelflow --workspace .sentinelflow tool run crtsh-subdomain-plus \
  --input plugins/official/crtsh-subdomain-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/crtsh-subdomain-plus/tests -v
```
