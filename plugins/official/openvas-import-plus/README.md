# openvas-import-plus

`openvas-import-plus` is an official SentinelFlow command plugin for importing
bounded OpenVAS or Greenbone report exports. It supports XML and CSV fixtures
and emits normalized vulnerability import records through a trusted built-in
parser.

The plugin does not run OpenVAS/GVM, connect to scanners, connect to targets, or
execute checks. It reads only plugin-local files, maps OpenVAS threat/severity
fields into SentinelFlow severity, preserves NVT OID/QoD metadata, and redacts
secret-like text in imported descriptions and result details.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/openvas-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/openvas-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run openvas-import-plus \
  --input plugins/official/openvas-import-plus/examples/input.fixture.xml.json \
  --authorization-scope fixture:local-only \
  --target openvas-fixture
python3 -m unittest discover -s plugins/official/openvas-import-plus/tests -v
```
