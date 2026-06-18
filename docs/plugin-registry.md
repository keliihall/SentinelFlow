# Plugin Discovery and Tool Registry

## Scope

P2-1 introduced discovery, validation, installation, registration, and query of tool
declarations. P2-2 may execute a declared runner only through Policy and the
controlled Command Adapter. Discovery, validation, installation, and registry
queries never execute plugin content.

Every plugin is integrated through its Manifest, package directories, and Schemas.
Adding a plugin does not require a change to `sentinelflow-core`.

Repository-maintained official plugins live under `plugins/official/`. They must
still pass the same package validation and runtime policy path as examples.

## Package Layout

```text
plugin-name/
  sentinelflow.tool.yaml
  runner/
  parser/
  schemas/
  examples/
  README.md
```

All entries must be real files or directories. Symbolic links are rejected during
validation and installation. `runner/` and `parser/` prove that the declared
integration boundaries exist; P2-1 does not load or invoke their contents.

Manifest `inputSchema` and `outputSchema` paths are relative to the plugin root.
Absolute paths and parent traversal are rejected.

## Discovery

The CLI registry scans `<workspace>/plugins/`, which defaults to
`.sentinelflow/plugins/`. The scanner also accepts arbitrary roots, including the
repository `plugins/examples/` and `plugins/official/` directories.

Discovery examines immediate child directories. It ignores:

- Hidden entries
- Editor and temporary entries
- Regular files at the plugin-root level
- Symbolic links

Discovered packages are not registered until every validation stage passes.

## Validation

`sentinelflow plugin validate <PATH>` reports five stages:

| Stage | Checks |
| --- | --- |
| `structure` | Required layout, YAML parsing, Rust decoding, JSON Schema |
| `semantic` | Manifest cross-field rules and resolvable Schema paths |
| `compatibility` | API compatibility, semantic tool version, supported runtime |
| `dependencies` | Runner, parser, input Schema, and output Schema presence |
| `safety` | Real directory, no symbolic links, safe tool/install name |

The Command Adapter supports only `runtime.mode: process`. Validation itself does not
start a process. Container mode remains unsupported and fails closed.

## Installation

```text
sentinelflow plugin install <PATH>
```

Installation validates before copying. The destination is
`<workspace>/plugins/<metadata.name>/`.

- Same name and same version: successful no-op; existing files are preserved.
- Same name and different version: version conflict; existing files are preserved.
- Invalid package or unsafe path: rejected before registration.
- New package: copied through a hidden staging directory and renamed into place.

Install attempts append a `sentinelflow.io/v1alpha1` `AuditEvent` to
`<workspace>/audit/events.jsonl`. The audit sink is opened before package state is
changed.

## Registry

The P2-1 registry is in memory and rebuilt from validated installed packages for each
CLI query. It supports registration, lookup, stable listing, enabled/disabled state,
same-version idempotency, and different-version conflicts.

Enabled state is exposed by the registry API and defaults to `true`. No enable or
disable CLI command is introduced in this milestone.

```text
sentinelflow tool list
sentinelflow tool info <TOOL>
```

`tool list` displays name, version, capabilities, risk levels, and enabled status.
`tool info` displays key Manifest, runtime, Schema, capability, and package details.

## Safe Example

`plugins/examples/example-echo/` declares one low-risk local echo capability. Its
input and output Schemas accept a bounded string. P2-2 includes a small executable
runner that reads and writes JSON only; there is no network access, scanning, or
system modification.

## Official Passive Plugin

`plugins/official/subdomain-discovery/` declares one low-risk passive discovery
capability. It queries only selected public data provider APIs, uses an embedded
`example.com` fixture for local acceptance, and records explicit safety counters
showing no DNS queries, brute force, dictionary candidates, port scans, or exploit
attempts.

## Plugin Development Guide

### Directory Structure

Create plugins with this layout:

```text
my-plugin/
  sentinelflow.tool.yaml
  README.md
  runner/
    run.py
  parser/
    README.md
  schemas/
    input.schema.json
    output.schema.json
  examples/
    input.json
    output.json
```

`runner/`, `parser/`, `schemas/`, and `examples/` must be real directories.
Symbolic links are rejected. The first release does not load untrusted parser
code in-process; `parser/README.md` documents the trusted built-in parser selected
by the Manifest.

### Manifest Writing

Start from `plugins/examples/example-echo/sentinelflow.tool.yaml`.

Required decisions:

- `metadata.name`: stable tool name used by `tool run` and Task Specs.
- `spec.capabilities`: capability name, description, `risk`, and
  `requiresApproval`.
- `spec.runtime.adapter`: optional; defaults to `command`. Use `docker`, `http`,
  or `fileImport` only when the plugin needs those adapters.
- `spec.runtime.mode`: `process` for Command/HTTP/File Import, `container` for
  Docker.
- `spec.runtime.timeoutSeconds`: bounded runtime timeout.
- `spec.runtime.outputLimitBytes`: bounded stdout/stderr or response size.
- `spec.parser.mode`: currently `builtin`.
- `spec.parser.name`: trusted parser name such as `example-echo-v1` or
  `example-file-import-v1`.
- `spec.inputSchema` and `spec.outputSchema`: plugin-root relative paths.

High and critical capabilities must set `requiresApproval: true`; otherwise
validation fails.

Validate a standalone JSON Manifest fixture:

```sh
target/debug/sentinelflow tool validate tests/fixtures/v1alpha1/valid-tool-manifest.json
```

Validate the whole plugin package:

```sh
target/debug/sentinelflow plugin validate plugins/examples/example-echo
```

### Runner Writing

Runner rules for `command` plugins:

- Read JSON from stdin.
- Write JSON to stdout.
- Write diagnostics to stderr only.
- Accept fixed Manifest `args`; do not build shell commands from input.
- Do not read arbitrary host paths.
- Do not access networks or real targets in examples.
- Exit non-zero for controlled failure.

Minimal safe runner shape:

```python
#!/usr/bin/env python3
import json
import sys

payload = json.load(sys.stdin)
message = payload.get("message")
if not isinstance(message, str):
    print("message must be a string", file=sys.stderr)
    raise SystemExit(2)
json.dump({"message": message}, sys.stdout, separators=(",", ":"))
```

### Parser Writing

v1.0-rc uses trusted built-in parsers. A plugin Manifest selects the parser; it
does not load parser code from the plugin process. The parser converts runner
JSON into a strict envelope:

```json
{
  "values": {"message": "hello"},
  "findings": [
    {
      "title": "Example echo completed",
      "severity": "info",
      "summary": "The safe example plugin returned a synthetic message.",
      "evidence": [
        {
          "evidenceType": "synthetic-message",
          "description": "Structured output emitted by the local example runner.",
          "data": {"message": "hello"}
        }
      ]
    }
  ],
  "errors": []
}
```

The Normalizer assigns stable `fingerprint` and `crossToolFingerprint`, removes
same-run duplicates, validates `ToolOutput`, and persists results.

### Local Testing

From a clean workspace:

```sh
cargo build --workspace
target/debug/sentinelflow --workspace .sentinelflow init
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow plugin test plugins/examples/example-echo
target/debug/sentinelflow --workspace .sentinelflow tool run example-echo \
  --input plugins/examples/example-echo/examples/input.json \
  --authorization-scope fixture:local-only \
  --target fixture-one
```

For Python SDK scaffolding:

```sh
target/debug/sentinelflow plugin scaffold /tmp/sentinelflow-python-example
target/debug/sentinelflow plugin validate /tmp/sentinelflow-python-example
target/debug/sentinelflow plugin test /tmp/sentinelflow-python-example
```

### Security Requirements

- No real scanners, exploits, brute force, credential use, stealth, persistence,
  bypass, or attack chains.
- Passive public-data plugins must not perform active DNS resolution, DNS brute
  force, dictionary enumeration, port scanning, exploitation, or attack-chain
  behavior.
- No plaintext credentials in Manifest files. Use environment-backed secret
  references where supported.
- No in-process dynamic library loading from untrusted plugins.
- No symbolic links in plugin packages.
- No parent traversal or absolute Schema paths.
- All execution must pass Policy, Audit, Parser, Normalizer, and Store.
- Examples must remain synthetic, bounded, and local-only.
