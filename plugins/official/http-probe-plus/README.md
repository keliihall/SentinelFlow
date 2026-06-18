# http-probe-plus

`http-probe-plus` is an official SentinelFlow command plugin for authorized
HTTP/HTTPS endpoint discovery and low-impact liveness validation.

It reports status code, redirect target, title, server header, content type,
content length, TLS usage, source agreement, and confidence. It does not perform
path brute force, vulnerability checks, credential testing, exploit attempts,
fuzzing, DoS, or arbitrary request execution.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without probes. |
| `passive_intel` | Local fixture/cache observations only. |
| `active_safe` | Bounded HTTP HEAD with optional small GET for titles. |
| `hybrid` | Passive observations plus bounded active HTTP verification. |

Active probing requires `policy.allow_active_verify=true` and is bounded by
timeout, concurrency, rate limit, max endpoints, max redirects, and max response
bytes. Non-fixture active probes keep only public routable hosts unless
`execution_profile=lab`.

## Acceptance

```sh
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/http-probe-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/http-probe-plus
target/debug/sentinelflow --workspace .sentinelflow tool run http-probe-plus \
  --input plugins/official/http-probe-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target example.com
python3 -m unittest discover -s plugins/official/http-probe-plus/tests -v
```
