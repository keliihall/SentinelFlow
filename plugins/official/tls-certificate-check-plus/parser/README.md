# Parser

The manifest selects trusted built-in parser `tls-certificate-check-plus-v1`.

The parser converts runner `tls_certificate_result` records into informational
`asset.tls_certificate` Findings and preserves structured fields under
`x-sentinelflow-tls-certificate.*`.
