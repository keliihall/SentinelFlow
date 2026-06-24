# Official Plugins

This directory contains SentinelFlow-maintained plugin manifests and fixtures
that are safe to validate through the standard Manifest, Adapter, Parser, Policy,
Audit, Schema, and Normalizer pipeline.

P5.6 status is explicit:

- `fixture-only`: may run only against local fixtures, mock/import data, or
  already-normalized SentinelFlow results.
- `disabled-p7-placeholder`: kept for manifest/API compatibility and future P7
  design, but not available as a P5.6 runtime capability.

No P5.6 official plugin is a default real asset discovery, active scanner,
public resolver verifier, port prober, service prober, or live external
intelligence provider.

- `subdomain-discovery-plus` is `fixture-only` only for Web Quick Run local
  fixtures in P5.6. Real subdomain discovery, live CT/provider discovery, and
  active DNS dictionary verification are `disabled-future` P7 placeholders.
- `subdomain-discovery`, `crtsh-subdomain-plus`, `dns-resolve-plus`,
  `ip-enrichment-plus`, `http-probe-plus`, `web-fingerprint-plus`,
  `tls-certificate-check-plus`, `fofa-import-plus`, `shodan-import-plus`,
  `censys-import-plus`, `port-probe-plus`, and `service-detect-plus` are
  `disabled-p7-placeholder` in P5.6.
- `nessus-import-plus` imports bounded Nessus XML, JSON, or CSV report fixtures
  into normalized vulnerability findings without invoking scanners or connecting
  to targets.
- `openvas-import-plus` imports bounded OpenVAS or Greenbone XML/CSV report
  fixtures into normalized vulnerability findings without invoking scanners or
  connecting to targets.
- `nuclei-adapter-plus` imports bounded Nuclei JSONL results with template path,
  severity, and tag policy controls without executing templates or invoking the
  `nuclei` binary.
- `zap-baseline-plus` imports bounded OWASP ZAP JSON/XML baseline reports,
  normalizes passive per-URL alerts, and applies risk, confidence, false-positive,
  deduplication, and redaction controls without invoking ZAP or connecting to
  targets.
- `cloud-asset-import-plus` imports bounded provider-native JSON inventories
  from Alibaba Cloud, Tencent Cloud, Huawei Cloud, AWS, and Azure, normalizing
  compute, public IP, load balancer, security group, DNS, object storage, WAF,
  and CDN assets without cloud credentials or API calls.
- `cmdb-sync-plus` imports bounded CMDB JSON/CSV inventories, normalizes
  department, business system, owner, lifecycle, and criticality metadata, and
  generates deterministic writeback operations for an approved CMDB gateway
  without directly mutating the CMDB.
- `markdown-report-plus` generates bounded, redacted Markdown delivery reports
  from already normalized SentinelFlow findings, errors, source status, and
  audit summaries without using user-supplied templates or external I/O.
