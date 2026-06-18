# Official Plugins

This directory contains SentinelFlow-maintained plugins that are safe to validate
and run through the standard Manifest, Adapter, Parser, Policy, Audit, Schema, and
Normalizer pipeline.

- `subdomain-discovery` performs passive subdomain discovery from public data
  providers only. It does not actively scan, brute force DNS, enumerate from
  dictionaries, probe ports, exploit vulnerabilities, or attack targets.
- `subdomain-discovery-plus` performs authorized passive fixture or optional
  `crt.sh` discovery and bounded active DNS dictionary verification when
  `policy.allow_active_verify=true`. It does not scan ports, test
  vulnerabilities, use credentials, or run attack chains.
- `crtsh-subdomain-plus` imports crt.sh-style certificate transparency data,
  cleans wildcard SAN names, extracts subdomain assets, and preserves
  certificate timeline evidence without active target connections.
- `dns-resolve-plus` performs DNS fixture/cache/passive-intel resolution by
  default and supports bounded active resolver verification only when
  `policy.allow_active_verify=true`.
- `ip-enrichment-plus` enriches IP assets with ASN, organization, ISP,
  geolocation, cloud provider, CDN/WAF signals, and local address
  classification without connecting to the target IP.
- `http-probe-plus` performs HTTP/HTTPS fixture/cache endpoint observation by
  default and supports bounded low-impact HTTP HEAD/GET verification only when
  `policy.allow_active_verify=true`.
- `web-fingerprint-plus` identifies CMS, framework, middleware, CDN/WAF, header,
  favicon, and low-impact body/title fingerprints from fixture/cache or upstream
  HTTP observations without making network requests.
- `tls-certificate-check-plus` inventories TLS certificate subject, issuer, SAN,
  validity, signature, TLS version, and expiry status from fixture/cache by
  default and supports bounded TLS handshakes only when
  `policy.allow_active_verify=true`.
- `fofa-import-plus` imports FOFA-style exposure intelligence from fixture/cache
  or a configured provider facade using only target-derived queries; arbitrary
  query strings are rejected and secrets are never emitted.
- `shodan-import-plus` imports Shodan-style host exposure intelligence from
  fixture/cache or a configured provider facade using only target-derived
  lookups; arbitrary search strings are rejected and secrets are never emitted.
- `censys-import-plus` imports Censys-style host, service, and certificate
  intelligence from fixture/cache or a configured provider facade using only
  target-derived lookups; arbitrary search strings are rejected and secrets are
  never emitted.
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
- `service-detect-plus` identifies services from upstream/cache/passive
  intelligence by default and supports policy-gated safe or high-risk detection
  frameworks without accepting arbitrary commands or exploit payloads.
