# Port Probe Plus

`port-probe-plus` keeps the port exposure manifest and fixture/cache import
shape for compatibility. In P5.6 it is `disabled-future`: TCP connect
verification, FOFA, and Shodan live provider calls are not available.

It does not implement SYN probing, external scanners, vulnerability checks,
credential testing, brute force, fuzzing, bypass, persistence, DoS, or exploit
chains.

`policy.allow_active_verify=true` does not enable TCP connect in P5.6.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without probes. |
| `passive_intel` | Local fixture/cache only in P5.6; FOFA/Shodan live calls are disabled. |
| `active_tcp_connect` | P7 placeholder; returns `P7_SCOPE_DISABLED` in P5.6. |
| `hybrid` | P7 placeholder unless active is disabled and only local fixture/cache inputs are used. |

FOFA and Shodan are reported as `skipped_p7_disabled` in P5.6.
