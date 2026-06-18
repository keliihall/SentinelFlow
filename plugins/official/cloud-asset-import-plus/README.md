# cloud-asset-import-plus

`cloud-asset-import-plus` imports provider-native JSON inventories from Alibaba
Cloud, Tencent Cloud, Huawei Cloud, AWS, and Azure. It supports compute, public
IP, load balancer, security group, DNS, object storage, WAF, and CDN assets.

The importer reads up to 32 plugin-local files, each no larger than 4 MiB. It
normalizes cloud identity, account/subscription/project scope, region, status,
public/private IPs, DNS names, tags, security rules, and internet exposure
signals. Secret-like tags are redacted.

This version never calls cloud APIs, reads credentials, connects to assets, or
changes cloud resources.

## Acceptance

```bash
target/debug/sentinelflow --workspace .sentinelflow plugin validate plugins/official/cloud-asset-import-plus
target/debug/sentinelflow --workspace .sentinelflow plugin install plugins/official/cloud-asset-import-plus
target/debug/sentinelflow --workspace .sentinelflow tool run cloud-asset-import-plus \
  --input plugins/official/cloud-asset-import-plus/examples/input.fixture.json \
  --authorization-scope fixture:local-only \
  --target multicloud-fixture
python3 -m unittest discover -s plugins/official/cloud-asset-import-plus/tests -v
```
