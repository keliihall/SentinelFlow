# Parser

The manifest selects trusted built-in parser `http-probe-plus-v1`.

The parser converts runner `http_result` records into informational
`asset.http_probe` Findings and preserves structured fields under
`x-sentinelflow-http.*`.
