# openvas-import-plus

`openvas-import-plus` is an official SentinelFlow command plugin for offline
OpenVAS or Greenbone report import. It converts bounded XML or CSV exports into
normalized vulnerability findings through the Manifest, Command Adapter,
built-in Parser, Policy, Audit, Schema, and Normalizer pipeline.

## Scope

- Imports plugin-local OpenVAS XML or CSV report files.
- Normalizes host, port, protocol, NVT OID, family, threat, QoD, CVE, CVSS,
  severity, evidence, and remediation metadata.
- Maps OpenVAS threat and numeric severity conservatively by keeping the higher
  severity when they disagree.
- Redacts secret-like text from imported descriptions, solutions, and evidence.
- Does not invoke OpenVAS/GVM, connect to scanners, connect to targets, use
  credentials, run exploit checks, or load dynamic libraries.

## Safety Boundary

The plugin is read-only and offline. Accepted files must resolve under
`plugins/official/openvas-import-plus/` and must be no larger than 4 MiB. Policy
requires `allow_active_verify=false` and `allow_high_risk=false`; execution still
requires an authorization scope.

## Acceptance Commands

```bash
cargo build -p sentinelflow-cli
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/openvas-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/openvas-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run openvas-import-plus \
  --input plugins/official/openvas-import-plus/examples/input.fixture.xml.json \
  --authorization-scope fixture:local-only \
  --target openvas-fixture
python3 -m unittest discover -s plugins/official/openvas-import-plus/tests -v
```

Repository-wide acceptance remains:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```
