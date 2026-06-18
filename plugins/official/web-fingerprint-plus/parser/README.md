# Parser

The manifest selects trusted built-in parser `web-fingerprint-plus-v1`.

The parser converts runner `web_fingerprint_result` records into informational
`asset.web_fingerprint` Findings and preserves structured fields under
`x-sentinelflow-web-fingerprint.*`.
