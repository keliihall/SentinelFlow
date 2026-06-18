# nuclei-adapter-plus

`nuclei-adapter-plus` is an official SentinelFlow command plugin for bounded
Nuclei JSONL result import. It normalizes Nuclei template findings into
SentinelFlow `risk.web_scan` findings through Manifest, Command Adapter, Policy,
Audit, Schema, built-in Parser, and Normalizer controls.

## Scope

- Imports plugin-local Nuclei JSONL output files.
- Normalizes matched URL, host, IP, scheme, port, template id/path/name,
  severity, tags, matcher/extractor names, CVE, CWE, CVSS, references, extracted
  results, and source details.
- Enforces template path allowlists and blocks destructive, intrusive, DoS, and
  RCE-style tags by default.
- Allows info/low template results by default; medium-or-higher severities must
  be explicitly enabled in the input policy options.
- Redacts secret-like descriptions and request metadata.

## Safety Boundary

The first version does not invoke `nuclei`, execute templates, connect to
targets, use credentials, load dynamic libraries, or accept arbitrary command
arguments. Accepted files must resolve under
`plugins/official/nuclei-adapter-plus/` and must be no larger than 4 MiB.

## Acceptance Commands

```bash
cargo build -p sentinelflow-cli
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/nuclei-adapter-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/nuclei-adapter-plus
target/debug/sentinelflow --workspace .sentinelflow tool run nuclei-adapter-plus \
  --input plugins/official/nuclei-adapter-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target https://www.example.com
python3 -m unittest discover -s plugins/official/nuclei-adapter-plus/tests -v
```

Repository-wide acceptance remains:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```
