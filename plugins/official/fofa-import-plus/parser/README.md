# Parser

The manifest selects trusted built-in parser `fofa-import-plus-v1`.

The parser converts runner `exposure_intel_result` records into informational
`asset.exposure_intel` Findings and preserves structured fields under
`x-sentinelflow-exposure-intel.*`.
