# Asset Discovery Flow

This document is a future P7 proposal. It is not a P5.6 runtime capability.

P5.6 remains fixture-only / passive-local / import / mock / governance
validation. It does not implement real asset discovery, active DNS verification,
public resolver verification, port probing, service probing, or live external
intelligence provider calls.

The proposed P7 asset discovery flow is designed as a low-disturbance,
multi-source, auditable chain:

```text
subdomain-discovery-plus
  -> crtsh-subdomain-plus
  -> dns-resolve-plus
  -> ip-enrichment-plus
  -> fofa-import-plus
  -> shodan-import-plus
  -> censys-import-plus
  -> port-probe-plus
  -> http-probe-plus
  -> web-fingerprint-plus
  -> tls-certificate-check-plus
  -> service-detect-plus
  -> markdown-report-plus
  -> Findings / Evidence / Report / Audit
```

The proposed P7 product posture is:

1. prefer non-intrusive multi-source intelligence;
2. keep fixture/cache inputs for stable CI and E2E;
3. allow active verification only after P7 scope approval, explicit
   configuration, and policy approval;
4. normalize, deduplicate, preserve sources, mark conflicts, and calculate confidence;
5. emit standard Finding/Evidence through Parser, Normalizer, Store, Report, and Audit.

## Modes

`fixture` is the only P5.6 executable mode for this family of examples. It reads
only repository fixtures and does not use external APIs or connect to real
targets.

`passive_intel` is P7 proposal language. In P5.6, live public intelligence
providers are disabled placeholders; local cache/import fixtures may be used for
governance validation only.

`active_safe` is a P7 proposal. In P5.6, `policy.allow_active_verify=true` is
not enough to enable active DNS, public resolver, TCP, HTTP, TLS, or service
probing.

`high-risk.example` is outside P5.6.

## Source Handling

DNS records are deduplicated by:

```text
domain + record_type + value
```

Service identities are deduplicated by:

```text
address + protocol + port + service + product + version
```

HTTP endpoints are deduplicated by:

```text
normalized URL
```

Web fingerprints are deduplicated by:

```text
normalized URL + technology
```

TLS certificate observations are deduplicated by:

```text
host + port + subject
```

Exposure intelligence imports are deduplicated by:

```text
host + ip + port
```

Markdown report artifacts are deduplicated by:

```text
report target + report title + rendered sections
```

Both plugins preserve `sources`, `source_details`, `source_count`,
`source_agreement`, `conflict`, `conflict_reason`, `stale`, and
`confidence_strategy`. Conflicts are never overwritten by later sources.

## Confidence

Confidence starts from source weights. Cache/fixture sources are lower
confidence, curated passive intelligence and upstream service intelligence are
middle confidence, and active verification sources are higher confidence.
Agreement across sources raises confidence; stale data and conflicts lower it.
Every final confidence is clamped to `[0, 1]`.

## Security Boundary

All tools still execute through Manifest + Adapter + Parser. Web Console and API
must reuse the existing orchestration path and must not run runners, shell,
Docker, or system commands directly.

P5.6 official plugins must not call live external APIs or connect to real
targets. Real secrets, production targets, exploit payloads, weak-password
dictionaries, and large scan targets must not be committed.

## Current DAG Limitation

The current v1.0-rc Task DAG uses one `target.input` shared by every step and
supports `inputFrom` only as a top-level field replacement. That is enough for
validate, plan, policy explain, and same-schema DAG examples, but a full
heterogeneous run across subdomain, DNS, port, and service schemas requires
step-specific input support or an already installed compatible `port-probe-plus`
flow contract. That heterogeneous chain remains P7 proposal material.

The examples under `docs/examples/task.subdomain-dns-port-service.*.yaml`
therefore document the intended chain and are safe for validate/plan/policy
review. P5.6 execution should stay on Web Quick Run fixture-only tasks or
explicit import/mock fixtures; DNS, port, service, HTTP, TLS, and external
intelligence plugins remain disabled P7 placeholders.
