# Parser

The manifest selects trusted built-in parser `openvas-import-plus-v1`.

The parser maps `vulnerability_import_result` records to standard Findings with
`findingType=risk.vuln_import`. OpenVAS-specific fields such as NVT OID, QoD,
threat, result ID, solution type, CVE, CVSS, source format, and source details
are preserved as structured Evidence metadata.
