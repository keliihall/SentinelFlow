# Nessus Import Plus

`nessus-import-plus` imports offline Nessus report exports through the standard
SentinelFlow Manifest, Command Adapter, Parser, Schema, Normalizer, Policy, and
Audit pipeline.

The plugin is for result import only. It does not run Nessus, authenticate to a
scanner, connect to targets, execute exploit checks, or validate credentials.

## Supported Inputs

- `.nessus` XML through `format=nessus_xml`
- JSON with a top-level `findings` array through `format=json`
- CSV rows through `format=csv`

All files must stay under the plugin package root for the first version. This
keeps CI fixtures deterministic and avoids arbitrary filesystem reads.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/nessus-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/nessus-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run nessus-import-plus \
  --input plugins/official/nessus-import-plus/examples/input.fixture.xml.json \
  --authorization-scope fixture:local-only \
  --target nessus-fixture
```
