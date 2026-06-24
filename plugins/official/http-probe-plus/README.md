# http-probe-plus

`http-probe-plus` is an official SentinelFlow command plugin for HTTP fixture
and cache validation. In P5.6 it is `disabled-p7-placeholder`: live HTTP/HTTPS
probing is not available.

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
| `active_safe` | P7 placeholder; returns `P7_SCOPE_DISABLED` in P5.6. |
| `hybrid` | P7 placeholder unless active is disabled and only local fixture/cache inputs are used. |

`policy.allow_active_verify=true` does not enable HTTP probing in P5.6.

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
