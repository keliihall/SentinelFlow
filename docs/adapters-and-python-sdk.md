# Adapters and Python SDK

## Capability Negotiation

| Adapter | Cancel | Stream logs | Resource limits | Async tasks |
| --- | --- | --- | --- | --- |
| Command | yes | no | no | no |
| Docker | yes | no | yes | no |
| HTTP | yes | no | no | yes |
| File Import | no | no | yes | no |

Capabilities describe implementation support; they never grant authorization.
Every Adapter invokes the shared default-deny Policy boundary during `prepare`.

## Adapter Controls

The Docker Adapter uses a Docker-compatible CLI argument array without a shell.
Networking defaults to `none`; mounts are limited to read-only plugin directories
beneath `examples/`; CPU, memory, timeout, output limits, cancellation, and
cleanup are enforced. Contract tests use a fake Docker CLI and need no daemon.

The HTTP Adapter supports GET/POST, non-sensitive headers, secret references,
retry, bounded pagination, and asynchronous polling. Plain HTTP is loopback-only;
pagination and polling remain same-origin; responses are size bounded.

The File Import Adapter accepts bounded JSON, JSONL, or CSV content directly in
the request. It never opens a caller-provided path.

## Python SDK

The dependency-free SDK in `sdk/python/` provides JSON stdin/stdout, standard
errors, Finding and Evidence drafts, parser envelopes, and handler test helpers.
Python plugins remain independent processes and do not modify Core.

```sh
PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests -v
sentinelflow plugin scaffold ./example-python-plugin
sentinelflow plugin test ./example-python-plugin
sentinelflow plugin validate ./example-python-plugin
sentinelflow plugin install ./example-python-plugin
sentinelflow tool run example-python-plugin \
  --input ./example-python-plugin/examples/input.json
```

`plugin test` installs into a temporary workspace and uses the normal Policy,
Audit, Adapter, Parser, and Normalizer pipeline.

## Finding Deduplication

The Normalizer computes SHA-256 fingerprints from title, severity, summary, and
evidence. The tool-scoped fingerprint includes the tool ID; the cross-tool
fingerprint does not. In-output duplicates are collapsed. The Store marks
historical same-tool matches first, then baseline cross-tool matches through
`duplicateOf`.

