# Parser

The manifest selects trusted built-in parser `ip-enrichment-plus-v1`.

The parser maps `ip_enrichment_result` records to standard Findings with
`findingType=asset.ip_enrichment`. ASN, ISP, geolocation, cloud/CDN/WAF signals,
address classification, confidence, and source details are preserved as
structured Evidence metadata.
