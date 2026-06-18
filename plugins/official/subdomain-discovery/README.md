# subdomain-discovery

`subdomain-discovery` is SentinelFlow's first official plugin. It performs
passive subdomain discovery by querying public data providers and normalizing the
returned hostnames into structured records.

## Safety Boundary

The plugin is passive-only:

- It queries only the selected public data provider APIs.
- It does not send DNS queries to discovered names.
- It does not brute force, enumerate from dictionaries, or mutate the root domain.
- It does not scan ports, test vulnerabilities, exploit targets, or run attack chains.
- It does not accept shell fragments, command arguments, credentials, or arbitrary files.
- It runs out of process through the Command Adapter and returns JSON over stdout.

The checked-in example uses `example.com`. For `example.com`, the runner returns an
embedded fixture so validation and CI do not depend on external network access.

## Input

```json
{
  "spec": {
    "root_domain": "example.com",
    "providers": ["crtsh", "hackertarget", "buffer_over"],
    "timeout": 30
  }
}
```

Supported providers:

- `crtsh`: Certificate Transparency search at `crt.sh`.
- `hackertarget`: HackerTarget host search API.
- `buffer_over`: BufferOver public DNS data API.

## Output

The runner emits a bounded structured object containing:

- `source`: fixed value `passive-subdomain-discovery`.
- `root_domain`: normalized root domain.
- `providers`: provider status and raw record counts.
- `records`: unique subdomain records with provider sources.
- `summary`: total unique subdomains.
- `safety`: passive-only counters for auditability.

The Manifest selects SentinelFlow's trusted built-in `example-file-import-v1`
parser. No parser code from this plugin directory is loaded in process.

## Acceptance Commands

```sh
cargo build --workspace
target/debug/sentinelflow --workspace .sentinelflow init
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/subdomain-discovery
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/subdomain-discovery
target/debug/sentinelflow --workspace .sentinelflow plugin test plugins/official/subdomain-discovery
target/debug/sentinelflow --workspace .sentinelflow tool run subdomain-discovery \
  --input plugins/official/subdomain-discovery/examples/input.json \
  --authorization-scope public:passive-discovery \
  --target example.com
```

