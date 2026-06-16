# Example Plugins

This directory contains safe, non-operational example plugins. Plugins must be
integrated through a Manifest, Adapter, and Parser, and must run out of process.

- `example-echo` echoes one bounded synthetic message.
- `example-dns-resolve` resolves approved names from an embedded mock table only.
- `example-file-import` imports bounded synthetic records supplied over stdin.
- `example-failure` exits with a controlled error for failure-policy tests.
- `example-slow` sleeps before output for timeout and cancellation tests.
- `example-invalid-parser` echoes local input through an intentionally invalid
  trusted parser for negative normalizer tests.
- `example-restricted-high-risk` performs local echo behavior while declaring a
  high-risk capability for approval E2E tests.
- `example-finding-consumer` consumes normalized synthetic Findings in DAG tests.
- `example-docker-adapter` demonstrates bounded Docker adapter configuration.
- `example-http-adapter` demonstrates loopback-only HTTP adapter configuration.
- `example-structured-import` demonstrates bounded structured import fixtures.

None of the examples scans, probes networks, opens arbitrary host paths, handles
credentials, or performs exploitation.

Copyable commands and task fixtures are documented in
[`docs/examples.md`](../../docs/examples.md).
