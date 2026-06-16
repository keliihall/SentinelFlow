# SentinelFlow v1.0-rc Release Notes

## Release Candidate Scope

`v1.0-rc` is intended for controlled local and team trials of SentinelFlow as a
tool-management framework. It includes CLI, API Service, Web Console, adapter
contracts, DAG planning, policy enforcement, audit, normalization, and reports.

This release candidate does not include plugin marketplace features, distributed
workers, AI analysis, advanced team spaces, real scanners, exploits, brute force,
stealth probing, persistence, bypass, or attack-chain automation.

## Required Release Gates

The default GitHub Actions CI workflow runs:

```sh
cargo fmt --all -- --check
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
tests/e2e/p5_5_smoke.sh
tests/e2e/p5_5_consistency.sh
tests/e2e/p5_5_full_flow/run.sh
tests/e2e/p5_5_security/run.sh
tests/e2e/p5_5_reliability/run.sh
tests/e2e/p5_5_deployment/run.sh
```

The performance baseline is a manual or scheduled release gate:

```sh
tests/performance/run.sh
```

Optional deployment gate:

```sh
docker compose up --build
```

Confirm `http://127.0.0.1:8080/health` returns `{"status":"ok"}`.

## Trial Credentials

Development-only identities:

- `viewer-token`
- `operator-token`
- `approver-token`
- `admin-token`

The local login password is `sentinelflow`. Production pilots must replace the
identity provider before using real users.

## Known Limits

- The single-machine deployment is the only supported deployment shape.
- v1.0-rc uses SQLite as the active store; PostgreSQL settings are reserved and
  intentionally not consumed by the runtime backend.
- Built-in identities and tokens are development/local-pilot credentials only;
  production-like pilots must use real authentication or a trusted reverse proxy.
- Single-node pilots should stay within the P5.5 performance baseline:
  4 recommended concurrent task runs, 20 concurrent API/Web users, 1,000
  findings per task, 2,000 task log events, and 5,000 findings per report.
- API sessions use the development identity provider by default.
- The Web Console is intentionally workflow-focused and not a dashboard.
- Only allowlisted repository example plugins and generated scaffold fixtures are
  executable under the current safety policy.
- The release-candidate container favors reproducible local builds over minimal
  image size and uses the Rust Debian base image for both build and runtime
  stages.

## Current Limits And Next Stage

The following are P6 planning areas and are not included in this release
candidate:

- Plugin marketplace and external plugin distribution.
- Distributed Worker execution.
- AI-assisted finding analysis.
- Advanced team collaboration spaces.

Do not treat v1.0-rc as a public production release. It is a controlled
single-node pilot candidate for safe local/synthetic validation workflows.
