# End-to-End Tests

This directory is reserved for isolated end-to-end tests using synthetic inputs and
explicitly authorized local test environments.

## P5.5 Smoke

```sh
tests/e2e/p5_5_smoke.sh
```

The script starts the local API service, logs in with the development operator
identity, validates and installs the safe `example-echo` plugin, plans and runs a
synthetic Task Spec, verifies logs and SSE cursor reconnect behavior, reads
findings, generates a report, and checks audit events.

## P5.5 CLI/API/Web Consistency

```sh
tests/e2e/p5_5_consistency.sh
```

The script builds the CLI and API, installs only safe example plugins into
isolated workspaces, drives the same P5.5 fixtures through CLI and API entry
points, verifies that the Web Console is API-only, compares semantic outcomes,
and writes `docs/release/p5_5_consistency_report.md`.

## P5.5 Full User Flow

```sh
tests/e2e/p5_5_full_flow/run.sh
```

The script starts a clean local API deployment and verifies four complete user
paths: low-risk execution, high-risk approval, mixed success/failure reporting,
and cancellation. It uses only local safe fixtures and writes
`docs/release/p5_5_e2e_report.md`.

## P5.5 Security Hardening

```sh
tests/e2e/p5_5_security/run.sh
```

The script starts a clean local API deployment and verifies authorization,
policy denial, audit, sensitive information redaction, plugin isolation, path
safety, command injection protection, parser invalid output, abnormal exits, and
API/Web bypass attempts. It writes
`docs/release/p5_5_security_hardening_report.md`.

## P5.5 Reliability

```sh
tests/e2e/p5_5_reliability/run.sh
```

The script starts and restarts a clean local API deployment, verifies task
state-machine audit events, abnormal task failure handling, report failure
audit, SSE reconnect cursors, duplicate execution rejection, duplicate approval
rejection, cancellation cleanup, and persisted task/log visibility after
restart. It writes `docs/release/p5_5_reliability_report.md`.

## P5.5 Deployment

```sh
tests/e2e/p5_5_deployment/run.sh
```

The script validates Docker Compose configuration, starts a clean API/Web
deployment, installs and runs `example-echo`, generates a report, verifies
SQLite schema metadata, and upgrades a previous-version workspace fixture while
preserving tools, tasks, runs, findings, audit, and reports. It writes
`docs/release/p5_5_deployment_report.md`.

## P5.5 Performance

```sh
tests/performance/run.sh
```

The script builds the local CLI/API binaries, starts an isolated API service,
drives safe synthetic `example-echo` workloads for concurrent API access, task
planning, task runs, audit writes, SSE logs, findings, and reports, then writes
raw metrics to `docs/release/p5_5_performance_baseline_metrics.json`. The
capacity baseline is documented in
`docs/release/p5_5_performance_baseline.md`.
