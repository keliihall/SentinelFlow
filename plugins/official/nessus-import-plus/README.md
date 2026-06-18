# nessus-import-plus

`nessus-import-plus` is an official SentinelFlow command plugin for importing
bounded Nessus report exports. It supports `.nessus` XML, JSON, and CSV fixtures
and emits normalized vulnerability import records through a trusted built-in
parser.

This plugin does not run Nessus, scan targets, authenticate to scanners, connect
to hosts, or execute plugin payloads. It reads only files under the plugin
directory, truncates long text fields, redacts secret-like content, maps
severity consistently, and preserves source report metadata for audit.

## Modes

- `fixture`: import a repository fixture file.
- `dry_run`: validate import configuration and report parser plan.
- `local_file`: import a bounded plugin-local file.

## Supported Formats

- `nessus_xml`: `.nessus` XML with `ReportHost` and `ReportItem` elements.
- `json`: structured JSON with a top-level `findings` array.
- `csv`: rows with host, port, protocol, service, plugin, severity, CVE, CVSS,
  synopsis, description, solution, and evidence columns.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/nessus-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/nessus-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run nessus-import-plus \
  --input plugins/official/nessus-import-plus/examples/input.fixture.xml.json \
  --authorization-scope fixture:local-only \
  --target nessus-fixture
python3 -m unittest discover -s plugins/official/nessus-import-plus/tests -v
```
