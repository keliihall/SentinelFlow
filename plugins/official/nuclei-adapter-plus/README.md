# nuclei-adapter-plus

`nuclei-adapter-plus` is an official SentinelFlow command plugin for bounded
Nuclei JSONL result import and normalization. The first version does not execute
the `nuclei` binary or run templates; it adapts already produced JSONL results
through SentinelFlow policy, schema, parser, audit, and normalization controls.

The plugin enforces template path allowlists, blocks destructive or intrusive
tags by default, requires explicit input approval for medium-or-higher template
results, redacts secret-like evidence, and emits structured web scan findings.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/nuclei-adapter-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/nuclei-adapter-plus
target/debug/sentinelflow --workspace .sentinelflow tool run nuclei-adapter-plus \
  --input plugins/official/nuclei-adapter-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target https://www.example.com
python3 -m unittest discover -s plugins/official/nuclei-adapter-plus/tests -v
```
