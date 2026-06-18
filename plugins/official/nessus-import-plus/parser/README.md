# Parser

The manifest selects trusted built-in parser `nessus-import-plus-v1`.

The parser maps runner `vulnerability_import_result` records to standard
Findings with `findingType=risk.vuln_import`. It preserves host, port, protocol,
service, Nessus plugin ID/name/family, CVE/CWE, CVSS, severity mapping,
synopsis, description, solution, evidence, source format, and source details as
structured Evidence metadata.
