# Port Probe Plus

`port-probe-plus` identifies authorized public port exposure using passive
sources first and optional bounded TCP connect verification.

It does not implement SYN probing, external scanners, vulnerability checks,
credential testing, brute force, fuzzing, bypass, persistence, DoS, or exploit
chains.

Active verification is limited to `tcp_connect` and requires
`policy.allow_active_verify=true`.

## Modes

| Mode | Purpose |
| --- | --- |
| `fixture` | Local synthetic examples and tests only. |
| `dry_run` | Configuration preview without probes. |
| `passive_intel` | Local cache and optional FOFA/Shodan enrichment. |
| `active_tcp_connect` | Bounded TCP connect checks only. |
| `hybrid` | Passive sources plus TCP connect verification. |

FOFA and Shodan are skipped gracefully when API keys are not configured in the
runtime environment.
