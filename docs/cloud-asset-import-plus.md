# cloud-asset-import-plus

`cloud-asset-import-plus` is SentinelFlow's bounded offline multi-cloud
inventory adapter.

## Coverage

- Providers: Alibaba Cloud, Tencent Cloud, Huawei Cloud, AWS, Azure.
- Resources: compute, public IP, load balancer, security group, DNS, object
  storage, WAF, CDN.
- Metadata: provider resource id, account/subscription/project scope, region,
  state, public/private addresses, DNS names, tags, and security rules.
- Analysis: deterministic deduplication, public exposure signals, secret tag
  redaction, and normalized info/low/medium risk labels.

Each source entry declares its provider and resource type so provider-native API
or CLI JSON envelopes can be decoded without guessing the inventory domain.
Multiple files can be imported in one run and filtered by provider, resource
type, or internet exposure.

## Safety boundary

The plugin performs offline import only. Cloud API calls, credential use, asset
connections, and resource mutation are schema-locked to `false`. It accepts at
most 32 regular JSON files below the plugin root, each limited to 4 MiB.

## Acceptance

```bash
cargo build -p sentinelflow-cli
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/cloud-asset-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/cloud-asset-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run cloud-asset-import-plus \
  --input plugins/official/cloud-asset-import-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target multicloud-fixture
python3 -m unittest discover -s plugins/official/cloud-asset-import-plus/tests -v
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```
