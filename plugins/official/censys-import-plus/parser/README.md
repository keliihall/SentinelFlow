# Parser

The manifest selects trusted built-in parser `censys-import-plus-v1`.

The parser maps raw `exposure_intel_result` records into standard SentinelFlow
Findings with `findingType=asset.exposure_intel` and
`x-sentinelflow-exposure-intel.provider=censys`. Censys-specific fields such as
certificate names, JARM, first/last observed timestamps, service fingerprint,
and source details are preserved as evidence metadata.
