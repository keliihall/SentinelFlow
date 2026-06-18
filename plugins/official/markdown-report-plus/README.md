# markdown-report-plus

`markdown-report-plus` is an official SentinelFlow command plugin that generates
bounded Markdown reports from already normalized SentinelFlow findings, errors,
and audit summaries.

It does not read the SentinelFlow store directly, make network requests, run
shell commands, load dynamic libraries, or accept arbitrary templates. The
runner consumes JSON supplied through the standard Command Adapter, redacts
secret-like values, limits report size, and emits a structured report artifact
that the trusted built-in parser normalizes.

## Modes

- `summary`: concise delivery report.
- `asset_discovery`: groups common asset discovery evidence categories.
- `audit`: emphasizes audit events and errors.

## Safety

- Input must be normalized SentinelFlow-style data.
- Markdown is generated from a fixed template.
- Secret-like keys and token-shaped values are redacted.
- Finding, evidence, audit, and output byte limits are enforced.
- The plugin is read-only and has no provider secrets.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/markdown-report-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/markdown-report-plus
target/debug/sentinelflow --workspace .sentinelflow tool run markdown-report-plus \
  --input plugins/official/markdown-report-plus/examples/input.asset-discovery.json \
  --authorization-scope fixture:local-only \
  --target report-fixture
python3 -m unittest discover -s plugins/official/markdown-report-plus/tests -v
```
